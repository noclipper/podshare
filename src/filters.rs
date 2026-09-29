//! The safety filters `podshare pack` and `send` apply. All are on unless the sender turns one off.
//! Agent config (hooks, MCP servers, settings) is not a filter: it is never shared.

use clap::ValueEnum;
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
pub enum Filter {
    /// Hide what the agent read outside the project folder
    OutsideProject,
    /// Leave out ~/Library (Messages, Mail), ~/Pictures, ~/.claude, ~/.config and similar
    PersonalFolders,
    /// Leave out .env files, keys, certificates, .ssh, .aws, databases and similar
    CredentialFiles,
    /// Leave out files the repo gitignores
    Gitignored,
    /// Redact keys and passwords in shared files and the transcript
    SecretScan,
    /// Hide output of shell commands podshare can't check: inline scripts, $(…), hidden-file globs, cd out of the project
    UncheckedCommands,
    /// Hide results of connected (MCP) tools such as a browser, mail or calendar
    ConnectedTools,
    /// Mask email addresses in the transcript
    Emails,
    /// Replace your home folder path and account name in the transcript
    Identity,
    /// Remove images pasted into the chat
    PastedImages,
    /// Leave out files over 10 MB (turn off to send them; they're still checked for secrets)
    LargeFiles,
    /// Leave out skills the chat used from outside the project (your own or a plugin's)
    PersonalSkills,
}

pub const ALL: [Filter; 12] = [
    Filter::OutsideProject,
    Filter::PersonalFolders,
    Filter::CredentialFiles,
    Filter::Gitignored,
    Filter::SecretScan,
    Filter::UncheckedCommands,
    Filter::ConnectedTools,
    Filter::Emails,
    Filter::Identity,
    Filter::PastedImages,
    Filter::LargeFiles,
    Filter::PersonalSkills,
];

impl Filter {
    pub fn name(self) -> String {
        self.to_possible_value().unwrap().get_name().to_string()
    }

    pub fn about(self) -> String {
        self.to_possible_value().unwrap().get_help().map(|h| h.to_string()).unwrap_or_default()
    }
}

#[derive(Default)]
pub struct Filters {
    off: Vec<Filter>,
    /// Project files the sender unticked; they and every call that read them stay out.
    pub excluded: BTreeSet<PathBuf>,
}

impl Filters {
    pub fn new(off: Vec<Filter>) -> Self {
        Filters { off, excluded: BTreeSet::new() }
    }

    pub fn on(&self, f: Filter) -> bool {
        !self.off.contains(&f)
    }

    pub fn toggle(&mut self, f: Filter) {
        match self.off.iter().position(|&o| o == f) {
            Some(i) => {
                self.off.remove(i);
            }
            None => self.off.push(f),
        }
    }

    /// Names of the filters that are off, in display order.
    pub fn off(&self) -> Vec<String> {
        ALL.iter().filter(|&&f| !self.on(f)).map(|f| f.name()).collect()
    }
}
