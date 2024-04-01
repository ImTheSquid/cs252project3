#![feature(iterator_try_collect)]

use is_terminal::IsTerminal;
use pest::{iterators::Pair, Parser};
use pest_derive::Parser;
use std::collections::HashSet;
use std::io::{prelude::*, stdin, stdout};
use std::path::{Path, PathBuf};
use std::process::Command;

use filedescriptor::FileDescriptor;
use signal_hook::consts::signal::*;
use std::fs::{File, OpenOptions};
use std::os::fd::FromRawFd;
use std::process::Stdio;
use std::sync::mpsc;
use std::sync::{Arc, RwLock, atomic::AtomicBool};
use termion::raw::IntoRawMode;
// A friend of the Signals iterator, but can be customized by what we want yielded about each
// signal.
use anyhow::bail;
use regex::Regex as RustRegex;
use signal_hook::iterator::exfiltrator::origin::WithOrigin;
use signal_hook::iterator::SignalsInfo;
use libc::c_int;

#[derive(Debug, Parser)]
#[grammar = "shell.pest"]
struct ShellParser;

#[derive(Debug, Clone)]
struct Context {
    current_command: Arc<RwLock<Option<u32>>>,
    active_daemons: Arc<RwLock<HashSet<u32>>>,
}

#[derive(Debug, Clone)]
enum CommandToken {
    Subshell(CommandSet),
    Literal(Vec<CompoundString>),
}

fn convert_wildcard_syntax(str: &str) -> String {
    str.replace('.', r#"\."#)
        .replace('*', ".*")
        .replace('?', ".")
}

fn expand_wildcards(path: &Path, previous_path_inclusions: usize) -> anyhow::Result<Vec<PathBuf>> {
    let (path, is_absolute) = if !path.to_string_lossy().starts_with('/') {
        (std::env::current_dir()?.join(path), false)
    } else {
        (path.to_path_buf(), true)
    };
    // Get first path component that contains a regular expression
    // Convert path component to regular expression, then convert the rest of the path as something
    // to use later
    let mut current_path = Vec::new();
    let mut regex = String::new();
    let mut next_path = Vec::new();
    for component in path.components() {
        let comp_str = component.as_os_str().to_string_lossy();
        if regex.is_empty() {
            if comp_str.contains('?') || comp_str.contains('*') {
                regex = format!("^{}", convert_wildcard_syntax(&comp_str));
            } else {
                current_path.push(comp_str);
            }
        } else {
            next_path.push(comp_str);
        }
    }

    if regex.is_empty() {
        return Ok(Vec::new());
    }

    let include_dots = regex.starts_with(r#"^\."#);
    let current_path = current_path.join("/");
    let current_path = current_path.replace("//", "/");
    let current_path = Path::new(&current_path);
    let regex = RustRegex::new(&regex)?;
    let next_path = next_path.join("/");
    let next_path = Path::new(&next_path);

    // Find all files and directories that match this regular expresion
    let mut found_files = Vec::new();
    let mut found_directories = Vec::new();

    if !current_path.is_dir() {
        return Ok(vec![current_path.into()]);
    }

    for item in current_path.read_dir()?.filter_map(Result::ok) {
        if regex.is_match(&item.file_name().to_string_lossy())
            && (!item.file_name().to_string_lossy().starts_with('.') || include_dots)
        {
            if include_dots && !item.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            // TODO: Symlinks?
            if item.file_type()?.is_dir() {
                found_directories.push(item.file_name());
            } else {
                found_files.push(item.file_name());
            }
        }
    }

    // If there aren't any more directories, we found all of the files that matched
    if next_path.components().count() == 0 {
        if include_dots {
            found_directories.append(&mut vec![".".into(), "..".into()]);
        }
        let mapped = found_files
            .into_iter()
            .chain(found_directories)
            .map(|s| Path::new(&s).to_path_buf())
            .map(|pa| {
                if is_absolute {
                    current_path.join(pa)
                } else {
                    let p = current_path
                        .components()
                        .skip(current_path.components().count() - previous_path_inclusions)
                        .collect::<PathBuf>();
                    p.join(pa)
                }
            })
            .collect::<Vec<_>>();
        return Ok(mapped);
    }

    // Replace the last component of the path with the found directories
    let found = found_directories
        .into_iter()
        .map(|dir| current_path.join(dir).join(next_path))
        .map(|dir_path| expand_wildcards(&dir_path, previous_path_inclusions + 1))
        .try_collect::<Vec<_>>()?;

    // Check if any items in current directory match
    // If is a directory, recurse into it, otherwise don't
    Ok(found.into_iter().flatten().collect())
}

// fn substitute_literal(lit: &str) -> String {
//     lit.split(' ')
//         .map(|tok| {
//             if tok.starts_with('$') {
//                 std::env::var(tok.strip_prefix('$').expect("prefix to exist"))
//                     .unwrap_or(String::new())
//             } else {
//                 tok.to_string()
//             }
//         })
//         .collect::<Vec<String>>()
//         .join(" ")
// }

fn process_string_single(lit: &str) -> anyhow::Result<String> {
    let re = RustRegex::new(r"\\(.)").unwrap();
    let output_string = re.replace_all(lit, |caps: &regex::Captures| {
        caps.get(1).unwrap().as_str().to_string()
    });
    Ok(expanduser::expanduser(output_string)
        .map(|p| p.to_str().expect("path to str").to_string())?)
}

fn process_string(compound: &[CompoundString]) -> anyhow::Result<String> {
    Ok(compound
        .iter()
        .map(|l| match l {
            CompoundString::String(s) => process_string_single(s),
            CompoundString::Env(e) => Ok(std::env::var(e).unwrap_or_default()),
        })
        .try_collect::<Vec<_>>()?
        .join(""))
}

impl CommandToken {
    fn exec_capture(&mut self, ctx: &mut Context) -> anyhow::Result<Vec<String>> {
        Ok(match self {
            Self::Subshell(cs) => cs
                .exec_capture(ctx)?
                .0
                .replace('\n', " ")
                .split(' ')
                .map(process_string_single)
                .try_collect::<Vec<_>>()?,
            Self::Literal(lit) => vec![process_string(lit)?],
        })
    }
}

trait Execute: std::fmt::Debug + std::marker::Send {
    fn exec(&mut self, ctx: &mut Context) -> anyhow::Result<()>;

    fn is_daemon(&self) -> bool;
}

/// Forces execution to return to stdout
trait ExecuteCapture: std::fmt::Debug + std::marker::Send {
    fn exec_capture(&mut self, ctx: &mut Context) -> anyhow::Result<(String, i32)>;
}

#[derive(Debug, Clone)]
struct SingleCommand {
    executable: CommandToken,
    args: Vec<CommandToken>,
}

#[derive(Debug)]
enum InfoSource {
    Default,
    File(filedescriptor::FileDescriptor, Option<c_int>),
    Execute(Box<CommandSet>),
}

impl Clone for InfoSource {
    fn clone(&self) -> Self {
        match self {
            Self::Default => Self::Default,
            Self::File(fd, _raw) => Self::File(FileDescriptor::dup(fd).expect("fd dup to succeed"), None),
            Self::Execute(cs) => Self::Execute(cs.clone()),
        }
    }
}

impl Drop for InfoSource {
    fn drop(&mut self) {
        if let Self::File(_, Some(raw)) = self {
            unsafe { libc::close(*raw); }
        }
    }
}

#[derive(Debug, Clone)]
struct CommandSet {
    commands: Vec<SingleCommand>,
    input: InfoSource,
    output: InfoSource,
    error: InfoSource,
    /// Ignored for subshells
    daemon: bool,
}

fn output_data(
    src: &mut InfoSource,
    is_err: bool,
    buf: Option<&mut String>,
    data: String,
) -> anyhow::Result<()> {
    if let Some(buf) = buf {
        *buf = data;
        return Ok(());
    }
    match src {
        InfoSource::Default => {
            if is_err {
                eprintln!("{data}")
            } else {
                println!("{data}")
            }
        }
        InfoSource::File(fd, _) => fd.write_all(data.as_bytes())?,
        InfoSource::Execute(_) => todo!(),
    }

    Ok(())
}

impl Execute for CommandSet {
    fn exec(&mut self, ctx: &mut Context) -> anyhow::Result<()> {
        self.run(ctx, false).map(|_| ())
    }

    fn is_daemon(&self) -> bool {
        self.daemon
    }
}

impl ExecuteCapture for CommandSet {
    fn exec_capture(&mut self, ctx: &mut Context) -> anyhow::Result<(String, i32)> {
        Ok(self.run(ctx, true)?.expect("captured result"))
    }
}

impl CommandSet {
    fn run(
        &mut self,
        ctx: &mut Context,
        capturing_result: bool,
    ) -> anyhow::Result<Option<(String, i32)>> {
        let num_commands = self.commands.len();

        let mut buffer = String::new();
        let mut last_exit = 1;

        for (i, command) in self.commands.iter_mut().enumerate() {
            let executable = command.executable.exec_capture(ctx)?;
            let args = command
                .args
                .iter_mut()
                .map(|a| a.exec_capture(ctx))
                .try_collect::<Vec<_>>()?;
            // We have executable and args, but they may need to be flattened
            let mut new_set = executable
                .into_iter()
                .chain(args.into_iter().flatten())
                .filter(|s| !s.is_empty());
            let executable = new_set.next().expect("at least command");
            // Also do wildcard expansion here because its easy
            let args = new_set
                .map(|arg| {
                    if arg.contains('*') || arg.contains('?') {
                        let expanded = expand_wildcards(Path::new(&arg), 0).map(|paths| {
                            let mut p = paths
                                .into_iter()
                                .map(|p| p.to_string_lossy().to_string())
                                .collect::<Vec<_>>();
                            p.sort();
                            p
                        });
                        if expanded.as_ref().is_ok_and(|e| e.is_empty()) {
                            Ok(vec![arg])
                        } else if let Err(e) = expanded {
                            Err(e)
                        } else {
                            expanded
                        }
                    } else {
                        Ok(vec![arg])
                    }
                })
                .try_collect::<Vec<Vec<String>>>()?;
            let args = args.into_iter().flatten().collect::<Vec<_>>();
            if !self.daemon {
                std::env::set_var("_", args.last().unwrap_or(&executable));
            }
            match executable.as_str() {
                "printenv" => {
                    let env = std::env::vars()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join("\n");
                    output_data(
                        &mut self.input,
                        false,
                        if i < num_commands - 1 {
                            Some(&mut buffer)
                        } else {
                            None
                        },
                        env,
                    )?;
                    continue;
                }
                "cd" => {
                    if args.len() > 1 {
                        bail!("Invalid arguments! Usage: cd [path]");
                    }
                    let path = if args.len() == 1 {
                        args[0].as_str()
                    } else {
                        "~"
                    };
                    let current = match std::fs::canonicalize(expanduser::expanduser(path)?) {
                        Ok(p) => p,
                        // The tests made me do this, I didn't wanna
                        Err(_) => {
                            output_data(
                                &mut self.error,
                                true,
                                if i < num_commands - 1 {
                                    Some(&mut buffer)
                                } else {
                                    None
                                },
                                format!("cd: can't cd to {}\n", args[0]),
                            )?;
                            continue;
                        }
                    };
                    std::env::set_current_dir(current)?;
                    continue;
                }
                "setenv" => {
                    if args.len() != 2 {
                        bail!("Invalid arguments! Usage: setenv <k> <v>");
                    }
                    std::env::set_var(&args[0], &args[1]);
                    continue;
                }
                "unsetenv" => {
                    if args.len() != 1 {
                        bail!("Invalid arguments! Usage: unsetenv <k>");
                    }
                    std::env::remove_var(&args[0]);
                    continue;
                }
                "source" => {
                    if args.len() != 1 {
                        bail!("Invalid arguments! Usage: source <file>");
                    }
                    run_script(&std::fs::read_to_string(&args[0])?, ctx, &mut None);
                    continue;
                }
                _ => {}
            }

            let input = if i == 0 {
                match self.input {
                    InfoSource::Default => Stdio::inherit(),
                    InfoSource::File(ref fd, _) => fd.as_stdio().expect("stdio conversion to succeed"),
                    InfoSource::Execute(ref _cs) => {
                        todo!()
                    }
                }
            } else {
                Stdio::piped()
            };

            let output = if i == num_commands - 1 {
                if capturing_result {
                    Stdio::piped()
                } else {
                    match self.output {
                        InfoSource::Default => Stdio::inherit(),
                        InfoSource::File(ref fd, _) => {
                            fd.as_stdio().expect("stdio conversion to succeed")
                        }
                        InfoSource::Execute(ref _cs) => {
                            todo!()
                        }
                    }
                }
            } else {
                Stdio::piped()
            };

            let error = if i == num_commands - 1 {
                match &self.error {
                    InfoSource::Default => Stdio::inherit(),
                    InfoSource::File(ref fd, _) => fd.as_stdio().expect("stdio conversion to succeed"),
                    InfoSource::Execute(ref _cs) => {
                        todo!()
                    }
                }
            } else {
                // stderr gets ignored in pipes
                Stdio::inherit()
            };

            let mut child = Command::new(executable)
                .args(args)
                .stdin(input)
                .stdout(output)
                .stderr(error)
                .spawn()?;

            if self.daemon {
                std::env::set_var("!", child.id().to_string());
            }

            // If there is a piped command before this, read from it for stdin
            if i > 0 {
                child
                    .stdin
                    .as_ref()
                    .expect("stdin to always be present")
                    .write_all(buffer.as_bytes())
                    .expect("pipe to write to stdin");
            }

            if self.daemon {
                ctx.active_daemons
                    .write()
                    .expect("active daemon write lock")
                    .insert(child.id());
            } else {
                let _ = ctx
                    .current_command
                    .write()
                    .expect("write op to succeed")
                    .insert(child.id());
            }

            let exit = child.wait().expect("Child to exit properly");

            // If there is a piped command after this, write to the buffer
            if i < num_commands - 1 || capturing_result {
                buffer.clear();
                child
                    .stdout
                    .as_mut()
                    .expect("stdout to always be present")
                    .read_to_string(&mut buffer)
                    .expect("pipe to read from stdout");
            } else if !self.daemon {
                // If not, clear current command buffer
                let _ = ctx
                    .current_command
                    .write()
                    .expect("write op to succeed")
                    .take();
            }

            let code = exit.code().unwrap_or(i32::MAX);
            last_exit = code;

            if !self.daemon {
                std::env::set_var("?", code.to_string());

                if code != 0 {
                    if let Ok(msg) = std::env::var("ON_ERROR") {
                        println!("{}", msg);
                    }
                }
            }
        }

        Ok(if capturing_result {
            Some((buffer, last_exit))
        } else {
            None
        })
    }
}

#[derive(Debug)]
struct If {
    condition: Box<dyn ExecuteCapture>,
    commands: Vec<Box<dyn Execute>>,
}

impl Execute for If {
    fn exec(&mut self, ctx: &mut Context) -> anyhow::Result<()> {
        let res = self.condition.exec_capture(ctx)?.1;

        if res == 0 {
            for command in &mut self.commands {
                command.exec(ctx)?;
            }
        }

        Ok(())
    }

    fn is_daemon(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct For {
    variable: String,
    iterator: Vec<CommandToken>,
    commands: Vec<Box<dyn Execute>>,
}

impl Execute for For {
    fn exec(&mut self, ctx: &mut Context) -> anyhow::Result<()> {
        let tokens: Vec<_> = self
            .iterator
            .iter_mut()
            .map(|ct| ct.exec_capture(ctx))
            .try_collect()?;

        // Yes I just copied this code from above, sue me
        // We have executable and args, but they may need to be flattened
        let new_set = tokens.into_iter().filter(|s| !s.is_empty()).flatten();
        // Also do wildcard expansion here because its easy
        let args = new_set
            .map(|arg| {
                if arg.contains('*') || arg.contains('?') {
                    let expanded = expand_wildcards(Path::new(&arg), 0).map(|paths| {
                        let mut p = paths
                            .into_iter()
                            .map(|p| p.to_string_lossy().to_string())
                            .collect::<Vec<_>>();
                        p.sort();
                        p
                    });
                    if expanded.as_ref().is_ok_and(|e| e.is_empty()) {
                        Ok(vec![arg])
                    } else if let Err(e) = expanded {
                        Err(e)
                    } else {
                        expanded
                    }
                } else {
                    Ok(vec![arg])
                }
            })
            .try_collect::<Vec<Vec<String>>>()?;
        let res = args.into_iter().flatten();

        for item in res {
            std::env::set_var(&self.variable, item);
            for command in &mut self.commands {
                command.exec(ctx)?;
            }
        }

        Ok(())
    }

    fn is_daemon(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct While {
    condition: Box<dyn ExecuteCapture>,
    commands: Vec<Box<dyn Execute>>,
}

impl Execute for While {
    fn exec(&mut self, ctx: &mut Context) -> anyhow::Result<()> {
        while self.condition.exec_capture(ctx)?.1 == 0 {
            for command in &mut self.commands {
                command.exec(ctx)?;
            }
        }

        Ok(())
    }

    fn is_daemon(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone)]
enum CompoundString {
    String(String),
    Env(String),
}

fn handle_compound_string(pair: Pair<'_, Rule>) -> Vec<CompoundString> {
    debug_assert!(
        matches!(pair.as_rule(), Rule::compound_string),
        "handle_compound_string used for non-compund string rule"
    );

    let pairs = pair.into_inner();
    pairs
        .map(|p| match p.as_rule() {
            Rule::unquoted_string => CompoundString::String(p.as_str().to_owned()),
            Rule::environment_variable => CompoundString::Env(
                p.into_inner()
                    .next()
                    .expect("env var inner")
                    .as_str()
                    .to_string(),
            ),
            _ => unreachable!(),
        })
        .collect()
}

fn handle_item(pair: Pair<'_, Rule>) -> Vec<CompoundString> {
    debug_assert!(
        matches!(pair.as_rule(), Rule::item),
        "handle_item used for non-item rule"
    );

    let pair = pair.into_inner().next().expect("string to be in item");
    match pair.as_rule() {
        Rule::compound_string => handle_compound_string(pair),
        Rule::string => {
            let inner = pair.into_inner().next().expect("inner contents");
            vec![CompoundString::String(inner.as_str().to_string())]
        }
        _ => unreachable!(),
    }
}

fn handle_item_or_subshell(pair: Pair<'_, Rule>) -> CommandToken {
    debug_assert!(
        matches!(pair.as_rule(), Rule::item_or_subshell),
        "handle_item_or_subshell used for non-item_or_subshell rule"
    );
    let pair = pair.into_inner().next().expect("only one item or subshell");
    match pair.as_rule() {
        Rule::item => CommandToken::Literal(handle_item(pair)),
        Rule::subshell => {
            let ssp = pair.into_inner().next().expect("subshell_program");
            CommandToken::Subshell(handle_program(ssp))
        }
        _ => unreachable!(),
    }
}

fn handle_command_arg(pair: Pair<'_, Rule>) -> SingleCommand {
    debug_assert!(
        matches!(pair.as_rule(), Rule::command_arg),
        "handle_command_arg used for non-command_arg rule"
    );
    let mut pairs = pair.into_inner();
    let command = pairs.next().expect("command");
    let command = handle_item_or_subshell(command);

    let args = pairs.map(handle_item_or_subshell).collect();

    SingleCommand {
        executable: command,
        args,
    }
}

#[derive(Debug)]
enum RedirectionToken {
    CommandToken(CommandToken),
    FileDescriptor(FileDescriptor, Option<c_int>),
}

fn handle_program(pair: Pair<'_, Rule>) -> CommandSet {
    debug_assert!(
        matches!(pair.as_rule(), Rule::program | Rule::subshell_program),
        "handle_program used for non-program rule"
    );
    let mut pairs = pair.into_inner();

    let commands = pairs
        .clone()
        .filter_map(|p| {
            if matches!(p.as_rule(), Rule::command_arg) {
                Some(handle_command_arg(p))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let mut input = InfoSource::Default;
    let mut output = InfoSource::Default;
    let mut error = InfoSource::Default;

    for redirection in pairs
        .clone()
        .filter(|p| matches!(p.as_rule(), Rule::redirection))
    {
        let mut pairs = redirection.into_inner();
        let redirection_type = pairs
            .next()
            .expect("redirection op to be present")
            .into_inner()
            .next()
            .expect("redirection op inner")
            .as_rule();

        let target = pairs.next().expect("redirection target to be present");
        let target = match target.as_rule() {
            Rule::item_or_subshell => {
                RedirectionToken::CommandToken(handle_item_or_subshell(target))
            }
            Rule::file_descriptor => {
                let target = target.into_inner().next().expect("fd");

                let fd = match target.as_rule() {
                    Rule::stdin => 0,
                    Rule::stdout => 3,
                    Rule::stderr => 4,
                    _ => unreachable!(),
                };

                // SAFETY: These file descriptors must always exist
                unsafe {
                    let fd = libc::dup(fd);
                    RedirectionToken::FileDescriptor(FileDescriptor::from_raw_fd(fd), Some(fd))
                }
            }
            _ => unreachable!(),
        };

        match redirection_type {
            Rule::truncate | Rule::append => {
                if !matches!(output, InfoSource::Default) {
                    println!("Ambiguous output redirect.");
                    std::process::exit(1);
                }

                output = match target {
                    RedirectionToken::FileDescriptor(fd, raw) => InfoSource::File(fd, raw),
                    RedirectionToken::CommandToken(ct) => match ct {
                        CommandToken::Literal(lit) => {
                            let file = OpenOptions::new()
                                .write(true)
                                .append(matches!(redirection_type, Rule::append))
                                .create(true)
                                .open(process_string(&lit).expect("string to process"))
                                .expect("file open to work");

                            InfoSource::File(FileDescriptor::new(file), None)
                        }
                        CommandToken::Subshell(cs) => InfoSource::Execute(Box::new(cs)),
                    },
                }
            }
            Rule::truncate_all | Rule::append_all => {
                (output, error) = match target {
                    RedirectionToken::FileDescriptor(fd, raw) => {
                        let second = FileDescriptor::dup(&fd).expect("duplication to succeed");
                        (InfoSource::File(fd, raw), InfoSource::File(second, raw))
                    }
                    RedirectionToken::CommandToken(ct) => match ct {
                        CommandToken::Literal(lit) => {
                            let file = OpenOptions::new()
                                .write(true)
                                .append(matches!(redirection_type, Rule::append_all))
                                .create(true)
                                .open(process_string(&lit).expect("string to process"))
                                .expect("file open to work");

                            let desc = FileDescriptor::new(file);

                            (
                                InfoSource::File(FileDescriptor::dup(&desc).expect("fd to dup"), None),
                                InfoSource::File(desc, None),
                            )
                        }
                        CommandToken::Subshell(cs) => (
                            InfoSource::Execute(Box::new(cs.clone())),
                            InfoSource::Execute(Box::new(cs)),
                        ),
                    },
                }
            }
            Rule::truncate_error => {
                error = match target {
                    RedirectionToken::FileDescriptor(fd, raw) => InfoSource::File(fd, raw),
                    RedirectionToken::CommandToken(ct) => match ct {
                        CommandToken::Literal(lit) => {
                            let file = OpenOptions::new()
                                .write(true)
                                .truncate(true)
                                .create(true)
                                .open(&process_string(&lit).expect("string to process"))
                                .unwrap_or_else(|e| {
                                    panic!("file open to work on path {lit:?} with error: {e}")
                                });

                            InfoSource::File(FileDescriptor::new(file), None)
                        }
                        CommandToken::Subshell(cs) => InfoSource::Execute(Box::new(cs)),
                    },
                }
            }
            Rule::read => {
                input = match target {
                    RedirectionToken::FileDescriptor(fd, raw) => InfoSource::File(fd, raw),
                    RedirectionToken::CommandToken(ct) => match ct {
                        CommandToken::Literal(lit) => {
                            let file = OpenOptions::new()
                                .read(true)
                                .open(&process_string(&lit).expect("string to process"))
                                .unwrap_or_else(|e| {
                                    panic!("file open to work on path {lit:?} with error: {e}")
                                });

                            InfoSource::File(FileDescriptor::new(file), None)
                        }
                        CommandToken::Subshell(cs) => InfoSource::Execute(Box::new(cs)),
                    },
                }
            }
            _ => unreachable!(),
        }
    }

    let daemon = pairs.any(|p| matches!(p.as_rule(), Rule::daemon));

    CommandSet {
        commands,
        input,
        output,
        error,
        daemon,
    }
}

fn handle_if_while(pair: Pair<'_, Rule>) -> Box<dyn Execute> {
    debug_assert!(
        matches!(pair.as_rule(), Rule::if_statement | Rule::while_statement),
        "handle_if_while used for non-if or while rule"
    );
    let rule = pair.as_rule();
    let mut pairs = pair.into_inner();

    // I <3 jank
    let condition = pairs.next().expect("condition").as_str();
    // Safety: this should always work since it's a valid command
    let condition = handle_program(
        ShellParser::parse(Rule::program, &format!("test {condition}"))
            .expect("successful parse")
            .next()
            .expect("at least one pair"),
    );
    let condition = Box::new(condition);

    let commands = pairs
        .next()
        .into_iter()
        .flat_map(|p| handle_program_list(p))
        .collect();

    match rule {
        Rule::if_statement => Box::new(If {
            commands,
            condition,
        }),
        Rule::while_statement => Box::new(While {
            condition,
            commands,
        }),
        _ => unreachable!(),
    }
}

fn handle_for(pair: Pair<'_, Rule>) -> Box<dyn Execute> {
    debug_assert!(
        matches!(pair.as_rule(), Rule::for_statement),
        "handle_for used for non-for rule"
    );
    let mut pairs = pair.into_inner();

    let variable = pairs.next().expect("variable").as_str().to_string();

    let iterator = pairs.next().expect("iterator");
    let iterator = iterator
        .into_inner()
        .map(|i| handle_item_or_subshell(i))
        .collect();

    let commands = pairs
        .next()
        .into_iter()
        .flat_map(|p| handle_program_list(p))
        .collect();

    Box::new(For {
        variable,
        iterator,
        commands,
    })
}

fn handle_control_flow(pair: Pair<'_, Rule>) -> Box<dyn Execute> {
    let pair = pair.into_inner().next().expect("control flow");
    match pair.as_rule() {
        Rule::if_statement => handle_if_while(pair),
        Rule::while_statement => handle_if_while(pair),
        Rule::for_statement => handle_for(pair),
        _ => unreachable!(),
    }
}

fn handle_program_list(pair: Pair<'_, Rule>) -> Vec<Box<dyn Execute>> {
    match pair.as_rule() {
        Rule::control_flow => vec![handle_control_flow(pair)],
        Rule::program => {
            let e: Box<dyn Execute> = Box::new(handle_program(pair));
            vec![e]
        }
        Rule::program_list => pair.into_inner().flat_map(handle_program_list).collect(),
        _ => unreachable!(),
    }
}

fn parse(cmd: &str, history: &mut Option<&mut Vec<String>>) -> Vec<Box<dyn Execute>> {
    let parsed = ShellParser::parse(Rule::program_list, cmd)
        .expect("successful parse")
        .next()
        .expect("at least one pair");

    let parsed = parsed.into_inner().collect::<Vec<_>>();
    if parsed.is_empty() {
        return vec![];
    }
    let skip = if !matches!(parsed[0].as_rule(), Rule::history_silence) {
        if let Some(history) = history.as_mut() {
            history.push(cmd.to_string());
        }
        0
    } else {
        1
    };

    parsed
        .into_iter()
        .skip(skip)
        .flat_map(handle_program_list)
        .collect()
}

fn run_script(contents: &str, ctx: &mut Context, history: &mut Option<&mut Vec<String>>) {
    if contents.trim_end().is_empty() {
        return;
    }
    let parsed = parse(contents, history);
    for mut parsed_command in parsed {
        if parsed_command.is_daemon() {
            let mut ctx = ctx.clone();
            std::thread::spawn(move || {
                if let Err(e) = parsed_command.exec(&mut ctx) {
                    println!("{}", e);
                }
            });
        } else if let Err(e) = parsed_command.exec(ctx) {
            println!("{}", e);
        }
    }
}

fn remove_char_at_index(input: &str, index: usize) -> String {
    let mut result = String::with_capacity(input.len() - 1);
    result.push_str(&input[..index]);
    result.push_str(&input[index + 1..]);
    result
}

fn insert_at_index(input: &str, c: &str, index: usize) -> String {
    let mut result = String::with_capacity(input.len() - 1);
    result.push_str(&input[..index]);
    result.push_str(c);
    result.push_str(&input[index..]);
    result
}

fn longest_common_prefix(s1: &str, s2: &str) -> String {
    let mut longest_prefix = String::new();

    for (ch1, ch2) in s1.chars().zip(s2.chars()) {
        if ch1 == ch2 {
            longest_prefix.push(ch1);
        } else {
            break;
        }
    }

    longest_prefix
}

fn longest_common_prefix_all(strings: &[String]) -> String {
    if strings.is_empty() {
        return String::new();
    } else if strings.len() == 1 {
        return strings[0].clone();
    }

    let middle = strings.len() / 2;

    let s1 = longest_common_prefix_all(&strings[..middle]);
    let s2 = longest_common_prefix_all(&strings[middle..]);

    longest_common_prefix(&s1, &s2)
}

fn main() {
    // SAFETY: All these file handles should exist. Anyways, this is necessary because
    // the fd crate im using acts really weird with termion, but this works just fine
    unsafe {
        libc::dup2(0, 3);
        libc::dup2(1, 4);
        libc::dup2(2, 5);
    };

    // Setup main context including active daemons, whatever the current command is, and any
    // context needed for the shell
    let active_daemons: Arc<RwLock<HashSet<u32>>> = Arc::new(RwLock::new(HashSet::new()));
    let active_daemons_sig = active_daemons.clone();
    let current_command = Arc::new(RwLock::new(None));
    let current_command_sig = current_command.clone();
    let mut history: Vec<String> = Vec::new();
    let mut ctx = Context {
        current_command,
        active_daemons,
    };

    // Set current shell PID
    std::env::set_var("$", std::process::id().to_string());

    // Create threads: signal, I/O, and executor
    // Signal thread handles Ctrl-C and SIGCHLD
    // I/O is what the user interacts with, and waits for active commands
    // Executor deals with spawning command instances and moving them around
    // Handle Ctrl-C
    enum TerminationType {
        Sigint,
        Sigchld(u32),
    }
    let (termination_tx, termination_buffer) = mpsc::channel::<TerminationType>();
    let mut sigs = SignalsInfo::<WithOrigin>::new([SIGINT, SIGCHLD]).expect("signals to hook");
    let sig_hnd = sigs.handle();
    let hnd = std::thread::spawn(move || {
        let mut kill_list = HashSet::new();

        for signal in &mut sigs {
            match signal.signal {
                SIGINT => {
                    let mut lock = current_command_sig
                        .write()
                        .expect("current command write lock");
                    if let Some(pid) = lock.take() {
                        kill_list.insert(pid);
                        // SAFETY: PID is known to exist, so is signal
                        unsafe {
                            libc::kill(pid as i32, libc::SIGINT);
                        }
                    } else {
                        termination_tx
                            .send(TerminationType::Sigint)
                            .expect("channel to be open");
                    }
                }
                SIGCHLD => {
                    if let Some(process) = signal.process {
                        let did_kill = kill_list.take(&(process.pid as u32)).is_some();
                        let did_daemon = active_daemons_sig
                            .write()
                            .expect("active daemons write lock")
                            .take(&(process.pid as u32))
                            .is_some();
                        if !(did_kill || did_daemon) {
                            continue;
                        }

                        termination_tx
                            .send(TerminationType::Sigchld(process.pid as u32))
                            .expect("channel to be open");
                    }
                }
                _ => unreachable!(),
            }
        }
    });

    // Try to source from .shellrc
    let shell_rc = Path::new(".shellrc");
    if shell_rc.is_file() {
        // This doesn't include history
        let mut f = File::open(shell_rc).expect("file to exist");
        let mut buf = String::new();
        f.read_to_string(&mut buf).expect(".shellrc load");
        run_script(&buf, &mut ctx, &mut None);
    }

    // Set ${SHELL}
    let exec = std::env::args().next().expect("exec path");
    std::env::set_var(
        "SHELL",
        std::fs::canonicalize(exec).expect("canonicalization of exec"),
    );

    // Check if there's a file provided as an argument. If so, just run the files line-by-line
    let mut args = std::env::args();
    let script = args.nth(1);
    if let Some(script) = script {
        std::env::set_var("#", (std::env::args().count() - 2).to_string());
        let remaining_args = args.collect::<Vec<_>>();
        std::env::set_var("*", remaining_args.join(" "));
        let remaining_args = vec![script.clone()]
            .into_iter()
            .chain(remaining_args)
            .collect::<Vec<_>>();
        for (i, arg) in remaining_args.iter().enumerate() {
            std::env::set_var(i.to_string(), arg);
        }

        let file = std::fs::read_to_string(script);
        match file {
            Ok(contents) => {
                run_script(&contents, &mut ctx, &mut Some(&mut history));
            }
            Err(e) => {
                eprintln!("Failed to read file! Error: {e}");
            }
        }
        return;
    }

    let is_terminal = std::io::stdin().is_terminal();

    if !is_terminal {
        let mut buf = String::new();
        stdin().read_to_string(&mut buf).expect("buf read ok");
        run_script(&buf, &mut ctx, &mut Some(&mut history));
        return;
    }

    let (tx, rx) = mpsc::channel();
    let run = Arc::new(AtomicBool::new(true));
    let run_thread = run.clone();
    let stdin_hnd = std::thread::spawn(move || {
        let stdin = OpenOptions::new().read(true).open("/dev/tty").expect("open dev tty");
        let mut hnd = nonblock::NonBlockingReader::from_fd(stdin).expect("nonblock");
        if hnd.is_eof() {
            return;
        }
        let mut buf = Vec::new();
        while run_thread.load(std::sync::atomic::Ordering::SeqCst) {
            let _ = hnd.read_available(&mut buf);
            for item in &buf {
                tx.send(*item).expect("tx send");
            }
            buf.clear();
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    });

    let mut stdout = stdout()
        .lock()
        .into_raw_mode()
        .expect("raw mode conversion");
    
    let mut input_buffer = String::new();
    let mut ignore_buffer = 0_usize;
    let mut current_history_position = -1_isize;
    let mut input_left_offset = 1;

    loop {
        write!(stdout, "{}\r", termion::clear::CurrentLine).expect("write ok");

        let prompt = std::env::var("PROMPT").unwrap_or("myshell>".to_string());

        if let Ok(new) = rx.try_recv() {
            if ignore_buffer > 0 {
                match new {
                    65 => {
                        current_history_position =
                            ((history.len() as isize) - 1).min(current_history_position + 1);
                    }
                    66 => {
                        current_history_position = (-1).max(current_history_position - 1);
                    }
                    68 => {
                        input_left_offset =
                            (input_buffer.len() as u16 + 1).min(input_left_offset + 1);
                    }
                    67 => {
                        input_left_offset = 1.max(input_left_offset - 1);
                    }
                    _ => {}
                }
                if new == 65 || new == 66 {
                    input_left_offset = 1;
                    if current_history_position > -1 && !history.is_empty() {
                        input_buffer.clone_from(&history[history.len() - 1 - current_history_position as usize]);
                    } else if current_history_position == -1 {
                        input_buffer.clear();
                    }
                }
                ignore_buffer -= 1;
                continue;
            }
            match new {
                127 => {
                    // Backspace
                    if input_buffer.len() as u16 + 1 - input_left_offset != 0 {
                        input_buffer = remove_char_at_index(
                            &input_buffer,
                            (input_buffer.len() as u16 - input_left_offset).into(),
                        );
                    }
                }
                13 => {
                    // Enter
                    stdout.suspend_raw_mode().expect("suspend raw");
                    println!("{prompt} {input_buffer}");
                    if input_buffer == "exit" {
                        break;
                    }

                    run_script(&input_buffer, &mut ctx, &mut Some(&mut history));
                    stdout.activate_raw_mode().expect("reenable raw");

                    input_buffer.clear();
                    input_left_offset = 1;
                    current_history_position = -1;
                }
                27 => {
                    ignore_buffer = 2;
                }
                1 => {
                    // Ctrl-A
                    input_left_offset = input_buffer.len() as u16 + 1;
                }
                3 => {
                    // Ctrl-C
                    stdout.suspend_raw_mode().expect("suspend raw");
                    println!("{prompt} {input_buffer}");
                    stdout.activate_raw_mode().expect("reenable raw");
                    input_buffer.clear();
                    input_left_offset = 1;
                    current_history_position = -1;
                }
                4 => {
                    // Ctrl-D
                    if input_left_offset > 1 {
                        input_buffer = remove_char_at_index(
                            &input_buffer,
                            (input_buffer.len() as u16 - input_left_offset + 1).into(),
                        );
                        input_left_offset -= 1;
                    }
                }
                5 => {
                    // Ctrl-E
                    input_left_offset = 1;
                }
                9 => {
                    // Tab
                    // Get current attached word
                    if input_buffer.is_empty() {
                        continue;
                    }
                    let splits = input_buffer[..=input_buffer.len() - input_left_offset as usize]
                        .split(' ')
                        .collect::<Vec<_>>();
                    match splits.last() {
                        None => continue,
                        Some(split) => {
                            if split.is_empty() {
                                continue;
                            }

                            match expand_wildcards(Path::new(&format!("{split}*")), 0) {
                                Ok(expanded) => {
                                    let candidates: Vec<_> = expanded
                                        .into_iter()
                                        .map(|p| p.to_string_lossy().to_string())
                                        .collect();
                                    let longest = longest_common_prefix_all(&candidates);
                                    let after = &input_buffer
                                        [input_buffer.len() - input_left_offset as usize + 1..];
                                    let mut before = splits.clone();
                                    before.pop();
                                    before.push(&longest);
                                    let mut res = before.join(" ");
                                    res.push_str(after);
                                    input_buffer = res;
                                }
                                Err(_) => continue,
                            }
                        }
                    }
                }
                _ => {
                    if input_buffer.is_empty() {
                        input_buffer.push(new as char);
                    } else {
                        input_buffer = insert_at_index(
                            &input_buffer,
                            &(new as char).to_string(),
                            (input_buffer.len() as u16 + 1 - input_left_offset) as usize,
                        );
                    }
                }
            }
        } 

        for term in termination_buffer.try_iter() {
            match term {
                TerminationType::Sigint => {
                    stdout.suspend_raw_mode().expect("suspend raw");
                    println!("{prompt} {input_buffer}");
                    stdout.activate_raw_mode().expect("reenable raw");
                }
                TerminationType::Sigchld(pid) => {
                    stdout.suspend_raw_mode().expect("suspend raw");
                    println!("{pid} exited.");
                    stdout.activate_raw_mode().expect("reenable raw");
                }
            }
        }

        write!(
            stdout,
            "{prompt} {input_buffer} {}",
            termion::cursor::Left(input_left_offset)
        )
        .expect("write ok");
        stdout.flush().expect("stdout flush");
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    stdout.suspend_raw_mode().expect("exit raw mode");
    unsafe {
        libc::close(3);
        libc::close(4);
        libc::close(5);
    }
    sig_hnd.close();
    hnd.join().expect("thread join");
    run.store(false, std::sync::atomic::Ordering::SeqCst);
    stdin_hnd.join().expect("stdin thread join");
    println!("buh bye");
}
