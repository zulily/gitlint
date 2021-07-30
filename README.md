# gitlint

A lint tool to scan your gitlab repos and report out stuff that violates the laws of order, discoverability, and tidiness.

gitlint will scan a repo and evaluate it against a number of rules and checks. The source is currently the authority on the evaluations, but here are a few highlights:
* Does your repo have a non-trivial Description?
* Is your repo private or internal? Why?
* Is your main branch called `main` or `master`?
* Do you have the 'Delete source branch on merge' enabled in project settings?
* Is there a readme with some amount of complexity, like Confluence links and several section headers?
* Is your repo forked from someone else's project? Again, why?
* Alternatively, list the forks of your repo so you get a reminder to nag them to delete the forks.
* Is there a gitlab CI script, and does it contain a ref to `dind`?
* Additional heuristics around activity, staleness, cruft, and recent successes for:
    * Commits
    * MRs
    * Branches
    * Pipelines
    * Deployments

gitlint currently covers a breadth of basics. Some key future enhancements should be focused on going deeper in a difficult area like: deployment script analysis; capturing and comparing results over time; making gitlint work as a part of daily toolchains (think: exclusions for some rules on some repos, configuration files, etc).

# Simple usage

To use the tool, you minimally need a gitlab personal API token (see below) and the name of a repo to evaluate.

`python gitlint.py group/SampleService --token <token>`
```
group: SampleService (group/sampleservice, id 3421)
  https://gitlab.sample.com/group/sampleservice
  last activity: 2021-05-26
SampleService: error: No description on this project.
SampleService: error: Trivially short readme has only 18 lines, needs improvement.
SampleService: error: 29 merged branches can be deleted.
SampleService: error: 43 stale branch(es) have not been touched in more than 90 day(s).
SampleService: error: 5 active Merge Requests, the newest is 71 day(s) old, the oldest is 521.
SampleService: warning: Turn on "[ ] Enable 'Delete source branch' option by default" in Settings | General | Merge Requests.
SampleService: warning: The readme has 0 section heading(s), should have at least 2 section(s).
SampleService: warning: Default branch is not 'main',currently called 'master' instead.
SampleService: warning: No commits for 36 day(s).
SampleService: warning: Quite a few branches, 48; clean these up.
SampleService: warning: No completed merge requests for 36 day(s).
SampleService: warning: There are 5 pending merge request(s) that do not have 'Delete source branch when merged' enabled.
SampleService: warning: No successful deployment(s) since 2021-06-24T06:55:02.243755.
```

NOTE: Because DORA Metrics are the new hotness, gitlint can be used to collect some basic deployment counts. Two things to note:
* The deployment counts (see issue #21) are currently an **info** level message, listed per-environment, so you'll need to use `-i` and prolly grep for `deployment` to get through the noise.
* The default date window for counting deployments is now - 7 days. Check the `--deployments-after` switch to use a different date.

Some simple notes on usage:
* The default CLI uses any non-switched parameter as a project name, so you can run it on multiple projects at once.
* You can pass a group name (e.g. `-g group`) to evaluate all non-archived repos in that group. You (the identity who created the token) must be a member of the group to enumerate the projects.
* You can add `-p` for pedantic checks, or `-i` for information level (outputs passing checks as well), or `-v` for verbose tracing.
* **Hit up the `-?` option!** All the options have fairly decent descriptions.

# Installing & Running

Requires Python and a couple of extra public pypi packages (which you can install with `pip install -r requirements.txt`). You can pollute your machine with direct installations of python and the packages. However, **we strongly recommend** you use something like venv to manage environments. Not gonna teach you that here, it's easy enough to [find on the web and worth learning](https://docs.python.org/3/library/venv.html#creating-virtual-environments).

* Python 3.7 or later
* python-gitlab
* pyyaml

You need a GitLab personal token. Go to your personal access token page in gitlab and generate a token with these permissions:

* api
* read_user
* read_api
* read_repository
* read_registry

Save that token somewhere (keychain or whatever) and then use it in the CLI as noted above. If you don't want to pass it on the CLI, you can set the `GITLINT_TOKEN` environment variable.

# Rules and Thresholds

Currently, gitlint evaluates the rules by a collection of methods that each look at some different aspect. These methods can conceptually be grouped into one of several areas:
* Project usability (readme, etc)
* Project settings (basic configuration)
* Deployments and Environments and Pipelines
* MRs and Branches and Commits

Each rule has been implemented by (hopefully) rather obvious code to check the condition. Where applicable, a separate configurable threshold value sets the key parameter for the evaluation code. The threshold limits are currently hardcoded and global for all repos evaluated in a run. In the future, we should instantiate the limits collection and rule inclusion/exclusion based on configuration files for the repo, as well as in a general 'config' file. The tedious part (thresholds) has been plumbed in. The more general part (getting the config into the tool, managing rules) is not yet done.

The grouping will be useful when refactoring the code into modules, expanding the scope of checks, and defining/implementing the rule configuration files.

# Contributing

Treat this like internal open source! Decide on a contribution, write it in a branch, create an MR, and get a maintainer to review. Check out **Pedantry** to learn about a few rules of the road.

Here are a few areas you can focus on:
* There are some issues. A few favorites:
    * dig deeper into quality of deployment script
    * add repo badges!
    * stats summary
* There are a bunch of TODOs in docstrings, future you and other engineers will thank you
* Use the tool and come up with your own ideas.

## Pedantry

### Toolability
The goal for gitlint is to be a packaged, deployable, remotable, robust tool that can be run automatically. This principle guides the implementation in the CLI and tool output, and should guide future implementation details like rule configuration, thresholds, and badging.

### Dependency checking in try/except
As a remotable tool, gitlint shouldn't rely on the normal blind `import` for dependencies without some care. So there's a try/except block at the top to catch import requirements and give a decent message. Also, gitlint checks its necessary python version, and a clear message emitted.

### Pythonic idioms and pylint
The pythonic rules can be idiomatic, but they exist and are followed. There are likely code patterns that aren't truly pythonic, but perhaps err'd toward understandability instead. YMMV.

The source should pass pylint at 100% (though, this isn't checked automatically right now). Most of this is generally compliant with pylint, including the tedious line length imported from a 1978-vintage VT100 Terminal. There are a very few exceptions that are excluded locally in the code with a comment on why. Keep this up.

### try / except
While it's not strictly pythonic to write try/except and continue, it's critical here in order to let the tool continue running on other projects. The process should continue even if one triggers an unhandled exception. If this occurs, gitlint dumps the offending stack trace in addition to the exception message. So there are a couple broad try/except blocks to achieve this. Don't lose sight of the value of these when writing a reusable tool.
