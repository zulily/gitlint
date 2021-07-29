"""
gitlint
    gitlint is a linter for gitlab repos. It scans repos and evaluates them for
    some specific requirements and expectations that tend to indicate how well
    they're maintained, how active they are, proper patterns of settings and
    usage, etc. It accepts a either a set of specific repos (projects) or
    one or more group names and enumerates all the repos in those groups.

    Copyright 2021 Zulily, LLC

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.

    You may obtain a copy of the License at
        https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
"""

# -----------------------------------------------------------------------------

import sys
import os
import re
from traceback import format_exc
from argparse import ArgumentParser, Namespace
from enum import IntEnum
from datetime import datetime, timedelta
from typing import List


def fatal(message: str, exit_code: int, show_stack=False) -> None:
    """
    A simple global fatal() implementation, should be used sparingly and only
    when there is really a catastrophic failure. It prints @message to stderr,
    then exit()s with @exit_code.
    """
    print(f'{sys.argv[0]}: fatal: {message}', file=sys.stderr)
    if show_stack:
        print(format_exc(), file=sys.stderr)
    sys.exit(exit_code)


# Let's do a quick requirements test before starting, looking at importing
# the non-standard bits we need. This try/except lets us capture problems
# and report an error that will read better than a stack trace in a log file
# when a machine isn't provisioned correctly.

try:
    import yaml
    import gitlab
    from gitlab.v4.objects import Project
    from gitlab.v4.objects import Group
    from gitlab.v4.objects import GroupProject

except (ImportError, ModuleNotFoundError) as import_ex:
    fatal('python-gitlab and pyyaml are required, at '
          'https://github.com/python-gitlab/python-gitlab and '
          'https://pyyaml.org/', os.EX_SOFTWARE)


class Config:
    """
    This is a singleton pattern for the Config class that contains
    truly single, global information about the tool's invocation.
    """

    # These next few flags are intended to enable gitlint to run as part of
    # a toolchain. They control how warnings are treated and manage the exit
    # codes when the tool runs.

    # CLI or settings file has indicated that warnings should be
    # treated like errors. This is accomplished in simple terms at
    # the report level by setting the 'has_...' variable if the run
    # has a warning while should_warn_as_error is effective.
    should_warn_as_error = False
    has_warn_as_error = False

    # Ditto for 'has_error' -- if any error was encountered, we need to
    # set the flag to return a non-zero exit code.
    has_error = False

    # If this is set, always pass the lint by returning a zero error code.
    always_pass = False

    no_sort_output = False

    # Gitlab-specific global defaults ---------

    # Holds the API token from ENV or CLI, used for all invocations
    gitlab_token: str = None

    # Holds the host name, can be repurposed at the CLI or ENV for
    # for some unforeseen scenario
    gitlab_host: str = 'https://gitlab.sample.com'

    # Name of the CI/CD configuration file, used if the project does
    # not contain its own special value (deviation is atypical).
    gitlab_ci_config_filename: str = '.gitlab-ci.yml'

    # Minimum number of days of inactivity for a branch to be
    # considered stale, Gitlab also reports these as "Stale Branches".
    branch_stale_days = 90

    # This is a 'lint_level: Severity' but we don't know about Severity
    # yet so it's just '1' by default, which is Error.
    lint_level = 1

    # Here are the collections of projects and groups to lint.

    # List of project names that take the form 'group/project' from the CLI.
    projects = []

    # List of all group IDs (integers) from the CLI with '--id <group_id>'.
    group_ids = []

    # List of all group names from the CLI with '--group <group_name>'.
    group_names = []

    # Starting date for when deployments should be counted. Comes from the CLI
    # with --deployments-after <string>
    deployments_after = None

    # Pylint doesn't recognize string slicing, it expects a __getitem__
    # method as if the subscript operators only work on lists. So since I'm
    # too lazy to rewrite the substring crap...
    # pylint: disable=E1136
    @staticmethod
    def obfuscated_token() -> str:
        """
        Constructs and returns an obfuscated string version of the
        gitlab token provided for authentication.
        """
        if not Config.gitlab_token or len(Config.gitlab_token) == 0:
            return '<none>'

        cleartext_len = 3
        tok: str = Config.gitlab_token
        return (tok[:cleartext_len] + '.' *
                (len(tok) - (cleartext_len * 2)) +
                tok[-cleartext_len:])
    # pylint: enable=E1136

    def __repr__(self):
        return f'{self.__class__.__name__}: {self.__class__.__dict__}'

    def __str__(self):
        message = f'{self.__class__.__name__}:\n'
        for (key, val) in self.__class__.__dict__.items():
            if key[:1] != '_':  # ignore private implementation details
                message += f'  {key}: {val}\n'
        return message


# -----------------------------------------------------------------------------

def main() -> int:
    """
    This is the main function of the gitlint tool. It constructs the
    gitlab access object, accumulates all the projects to evaluate,
    then runs the evaluations and reports for those projects.

    :return: Process exit code
    """

    LintReport.trace(f'Running against {Config.gitlab_host} with '
                     f'token \'{Config.obfuscated_token()}\'.')
    lab = gitlab.Gitlab(Config.gitlab_host,
                        private_token=Config.gitlab_token)

    target_projects = assemble_project_list(lab)

    # This is the main loop, once we've got a big list of repos to look at.
    for proj in target_projects:
        # The original projects list could have GroupProject objects in it,
        # if they came by loading all projects for a given group. GroupProjects
        # are lighter and faster and created when the list is created with
        # Lazy=True. So, if the member of the list is actually not a Project
        # but is instead a GroupProject, we have to convert it before running
        # the evaluation.
        if isinstance(proj, GroupProject):
            run = evaluate_project(lab.projects.get(proj.id))
        else:
            run = evaluate_project(proj)

        # Right now, we just show the output in this main loop. Might change
        # that in the future.
        display_lint_report(run)

    if Config.always_pass:
        LintReport.trace('The \'always pass\' switch was present, so '
                         'regardless the outcome we will return success.')
        return os.EX_OK

    if Config.has_warn_as_error:
        LintReport.trace('Found at least one warning with warn-as-error on, '
                         'exiting with non-zero return code.')
        return 1

    if Config.has_error:
        LintReport.trace('Found at least one error, '
                         'exiting with non-zero return code.')
        return 1

    return os.EX_OK


def assemble_project_list(lab: gitlab) -> list:
    """
    Collect all the projects from the three sources: the explicit
    project names, and all the projects within the group(s) identified
    with either their name or their ID.

    :param lab: gitlab is the accessor for the Gitlab server
    :return: list of all projects assembled from project names and groups
    :rtype: list
    """
    target_projects = []

    try:
        if Config.projects and len(Config.projects) > 0:
            LintReport.trace('Adding non-group projects by name.')
        for proj in Config.projects:
            try:
                target_projects.append(lab.projects.get(proj))
            except gitlab.exceptions.GitlabGetError as ex:
                print(f'Cannot load project \'{proj}\', error {ex}.')

        for group_id in Config.group_ids:
            projects = get_projects_for_group_id(lab, group_id)
            for proj in projects:
                target_projects.append(proj)

        for group_name in Config.group_names:
            projects = get_projects_for_group_name(lab, group_name)
            for proj in projects:
                target_projects.append(proj)

    except (gitlab.exceptions.GitlabAuthenticationError,
            ConnectionError) as error:
        fatal(f'Cannot access Gitlab at {Config.gitlab_host} with '
              f'token \'{Config.obfuscated_token()}\':\n{error}',
              os.EX_NOPERM)

    return target_projects


# -----------------------------------------------------------------------------

class Severity(IntEnum):
    """
    Embodies the severity of a diagnostic failure, including the message label.
    """

    FATAL = 0
    ERROR = 1
    WARNING = 2
    PEDANTIC = 3
    INFO = 4
    VERBOSE = 5

    def __str__(self):
        return {
            Severity.FATAL: 'fatal',
            Severity.ERROR: 'error',
            Severity.WARNING: 'warning',
            Severity.PEDANTIC: 'pedantic',
            Severity.INFO: 'info',
            Severity.VERBOSE: 'verbose',
        }.get(self)

    def __repr__(self):
        return f'{self.__class__}{self}({int(self)})'


class Diagnosis:
    """
    An instance of a diagnostic failure,
    captures severity and message details.
    """

    def __init__(self, t: Severity, m: str):
        self.level = t
        self.message = m

    def __str__(self):
        return f'{str(self.level)}: {self.message}'

    def __repr__(self):
        return f'Diagnosis({str(self.level)}, {self.message})'


# Seems that PyLint doesn't like how many members, or how few methods, are
# in this class. I guess they could be a dictionary instead of a class?
# pylint: disable=R0902, R0903
class Thresholds:
    """
    An instance of a set of thresholds and configuration data that is
    specific to a single repo/project.
    """

    def __init__(self):
        self.readme_lines_min = 50
        self.readme_confluence_link_min = 1
        self.readme_heading_min = 2
        self.description_words_min = 10
        self.activity_stale_days_error = 180
        self.activity_stale_days_warning = 90
        self.activity_stale_days_pedantic = 15
        self.pipeline_stale_days_error = 180
        self.pipeline_stale_days_warning = 90
        self.pipeline_stale_days_pedantic = 30
        self.pipeline_backlog_count_max = 10
        self.commit_stale_days_error = 180
        self.commit_stale_days_warning = 30
        self.commit_stale_days_pedantic = 15
        self.merge_stale_days_error = 180
        self.merge_stale_days_warning = 30
        self.merge_stale_days_pedantic = 15
        self.pending_merge_oldest_error = 90
        self.pending_merge_newest_error = 30
        self.pending_merge_newest_warning = 8
        self.pending_merge_newest_pedantic = 3
        self.pending_merge_max = 5
        self.branch_merged_error = 20
        self.branch_merged_warning = 5
        self.branch_merged_pedantic = 0
        self.branch_count_error = 100
        self.branch_count_warning = 30
        self.branch_count_pedantic = 10
        self.branch_stale_count_error = 30
        self.branch_stale_count_warning = 10
        self.branch_stale_count_pedantic = 0

# pylint: enable=R0902, R0903


class LintReport:
    """
    Captures a gitlab Project and the result set of all diagnostic evaluations.
    """

    def __init__(self, proj: Project, rules: list = None,
                 limits: Thresholds = None):
        self.proj = proj
        self.messages = []
        self.rules = rules
        self.limits = limits
        self.is_archived = False

    def error(self, message: str, show_stack=False) -> None:
        """ Records an Error-level diagnostic message. """
        self.messages.append(Diagnosis(Severity.ERROR, message))
        if show_stack:
            self.messages.append(Diagnosis(Severity.ERROR, format_exc()))

    def warning(self, message: str) -> None:
        """ Records a Warning-level diagnostic message. """
        self.messages.append(Diagnosis(Severity.WARNING, message))

    def pedantic(self, message: str) -> None:
        """ Records a Pedantic-level diagnostic message. """
        self.messages.append(Diagnosis(Severity.PEDANTIC, message))

    def info(self, message: str) -> None:
        """ Records an Info-level diagnostic message. """
        self.messages.append(Diagnosis(Severity.INFO, message))

    @staticmethod
    def trace(message: str) -> None:
        """ Displays a trace message to the console, if Verbose is set. """
        if Config.lint_level >= Severity.VERBOSE:
            print(f' - {message}')


# -----------------------------------------------------------------------------

def display_lint_report(run: LintReport) -> None:
    """
    Iterates over all the strings collected in the LintReport, sorts and
    filters according to thresholds, manages the warn_as_error logic, and
    prints out the appropriate messages in the report.

    :param run: LintReport
    """
    proj: Project = run.proj

    LintReport.trace(f'Evaluation has {len(run.messages)} messages, '
                     'ordering by severity.')

    print(f"{proj.namespace['name']}: {proj.name} "
          f'({proj.path_with_namespace}, id {proj.id})')

    last_act = convert_api_datetime(proj.last_activity_at).date()
    print(f'  {proj.web_url}\n  last activity: {last_act}')

    if not Config.no_sort_output:
        # List the messages in severity order
        run.messages.sort(key=lambda x: x.level, reverse=False)

    for msg in run.messages:
        if msg.level == Severity.ERROR:
            Config.has_error = True

        if Config.should_warn_as_error and msg.level == Severity.WARNING:
            # Not thrilled with mutating this object, but it makes the point
            msg.level = Severity.ERROR
            Config.has_warn_as_error = True

        # If we wanted to do alternate output formats or targets, this is
        # where to do it.
        if msg.level <= Config.lint_level:
            print(f'{proj.name}: {msg}')


# -----------------------------------------------------------------------------

def evaluate_archive_status(run: LintReport) -> bool:
    """
    Iterates over all the strings collected in the LintReport, sorts and
    filters according to thresholds, manages the warn_as_error logic, and
    prints out the appropriate messages in the report.

    :param run: LintReport
    :return: Indicator of whether the repo is archived, shouldn't be checked.
    :rtype: bool
    """
    if run.proj.archived:
        run.info('Archived repo, no further evaluation.')
        run.is_archived = True

    LintReport.trace('Repo is not archived, continuing evaluation.')
    return run.is_archived


def evaluate_project_settings(run: LintReport) -> None:
    """
    Looks at whether the project has some basic settings in the recommended
    state:
        * 'Delete source branch' as a MR default

    :param run: LintReport
    """
    if not run.proj.remove_source_branch_after_merge:
        run.warning('Turn on "[ ] Enable \'Delete source branch\' option by '
                    'default" in Settings | General | Merge Requests.')


def evaluate_description(run: LintReport) -> None:
    """
    Evaluates whether the project has a non-trivial description. Uses
    Threshold.description_words_min as the threshold, and assumes word
    separation is ' ' (.split() method).

    :param run: LintReport
    """
    if not run.proj.description or len(run.proj.description) == 0:
        run.error('No description on this project.')

    elif len(run.proj.description.split()) < run.limits.description_words_min:
        run.warning('Trivial description.')
    else:
        run.info('Decent description.')


def evaluate_visibility(run: LintReport) -> None:
    """
    Evaluates whether the project is hidden or internal, and biases toward
    public (why hide this inside our private gitlab server?).

    :param run: LintReport
    """
    if run.proj.visibility == 'internal':
        run.info('Internal project, network with authentication.')
    elif run.proj.visibility == 'public':
        run.pedantic('Public project, network with no authentication.')
    else:
        run.warning('Private project, why is this hidden from search?')


def evaluate_readme(run: LintReport) -> None:
    """
    TODO:

    :param run: LintReport
    """
    if not run.proj.readme_url or len(run.proj.readme_url) == 0:
        run.error('No readme recognized by gitlab.')
        return

    readme = os.path.basename(run.proj.readme_url)
    file = get_file_from_project(run.proj, readme)
    if not file:
        run.error(f'The readme file \'{readme}\'cannot be fetched.')
        return

    readme_text = file.decode()

    num_lines = len(readme_text.split('\n'))
    if num_lines >= run.limits.readme_lines_min:
        run.info('The readme meets length requirement '
                 f'(more than {run.limits.readme_lines_min} lines).')
    else:
        run.error('Trivially short readme has only '
                  f'{num_lines} lines, needs improvement.')

    num_confluence = readme_text.count('confluence.sample.com')
    if num_confluence >= run.limits.readme_confluence_link_min:
        run.info('The readme has at least '
                 f'{run.limits.readme_confluence_link_min} link(s) '
                 'to the team\'s Confluence pages.')
    else:
        run.warning('The readme should have at least '
                    f'{run.limits.readme_confluence_link_min} link(s) '
                    'to the team\'s Confluence pages.')

    if readme.lower().endswith('.md'):
        LintReport.trace('Readme is markdown, looking for section headers.')

        # Since it's markdown, we want it to have some number of section
        # headings, indicating a bit of complexity
        num_headings = len(re.findall('\n##?#? ', readme_text))
        if num_headings >= run.limits.readme_heading_min:
            run.info(
                    f'The readme has at least {run.limits.readme_heading_min} '
                    'section heading(s).')
        else:
            run.warning(f'The readme has {num_headings} section heading(s), '
                        'should have at least '
                        f'{run.limits.readme_heading_min} section(s).')


def evaluate_recent_activity(run: LintReport) -> None:
    """
    TODO:

    :param run: LintReport
    """
    delta = get_delta_days(run.proj.last_activity_at)

    message = f'No activity for {delta} day(s).'
    if delta > run.limits.activity_stale_days_error:
        run.error(message)
    elif delta > run.limits.activity_stale_days_warning:
        run.warning(message)
    elif delta > run.limits.activity_stale_days_pedantic:
        run.pedantic(message)
    else:
        run.info('Activity level seems busy enough, last activity was '
                 f'{delta} day(s) ago.')


def evaluate_forked(run: LintReport) -> None:
    """
    Evaluates whether the project was forked from some other project, and
    bias toward not forking.

    :param run: LintReport
    """
    if (hasattr(run.proj, 'forked_from_project') and
            run.proj.forked_from_project):
        parent = run.proj.forked_from_project['path_with_namespace']
        run.warning(f'Forked from {parent}, why would you do that?')
        run.info('Since this is forked, you should either be sending '
                 'changes back upstream to the parent repo, or regularly '
                 'pulling updates from the parent. Otherwise, this repo '
                 'is just copy pasta.')


def evaluate_forks(run: LintReport) -> None:
    """
    TODO:

    :param run: LintReport
    """
    count = run.proj.forks_count
    if count:
        LintReport.trace(f'Found {count} forks to nag.')
        forks = run.proj.forks.list()
        if len(forks) == 0:
            forkers = '(private), '
        else:
            forkers = ''
        for fork in forks:
            if len(fork.path_with_namespace) == 0:
                forkers += '(private), '
            else:
                forkers += f'{fork.path_with_namespace}, '
        run.warning(f'Forked by {count} project(s): {forkers[:-2]}.')
        run.info('Take the \'Forked by...\' list and go nag '
                 'the teams to delete their forks.')
    else:
        run.info('No forks of this project.')


def evaluate_subprojects(run: LintReport) -> None:
    """
    TODO:
    Are there smells or bad patterns to look at if a project has subprojects?
    Should we recurse into the subs, evaluate them as top-level projects?

    :param run: LintReport
    """
    _ = run


def evaluate_ci_config(run: LintReport) -> None:
    """
    TODO:

    :param run: LintReport
    """
    config_path = Config.gitlab_ci_config_filename
    if run.proj.ci_config_path and len(run.proj.ci_config_path) > 0:
        LintReport.trace('Project has override for ci_config_path, '
                         f' using {config_path}.')
        config_path = run.proj.ci_config_path

    file = get_file_from_project(run.proj, config_path)
    if not file:
        run.warning(f'No CI script ({config_path}), '
                    'is this a production service project?')
        return

    run.info(f'Evaluating CI configuration at \'{config_path}\'.')
    yam = yaml.load(file.decode(), Loader=yaml.FullLoader)
    if 'services' in yam:
        services = yam['services']
        run.info('Looking for Docker-in-Docker (dind) in the services.')
        for svc in services:
            if re.match('docker:.*dind', svc, re.IGNORECASE):
                run.error(f'CI configuration ({config_path}) includes '
                          f'reference to Docker-in-Docker service \'{svc}\', '
                          'which is deprecated and troublesome; remove it.')


def evaluate_pipelines(run: LintReport) -> None:
    """
    TODO:

    :param run: LintReport
    """
    try:
        # This could throw a GitlabListError from the list() method
        pipelines = run.proj.pipelines.list(
                per_page=run.limits.pipeline_backlog_count_max)
        if len(pipelines) == 0:
            run.info('There are no pipelines, '
                     'is this a production service project?')
            return

        if pipelines[0] and pipelines[0].status == 'failed':
            run.warning('Most recent pipeline failed.')

        for pipe in pipelines:
            if pipe.status == 'success':
                delta = get_delta_days(pipe.updated_at)
                message = f'No successful pipelines for {delta} day(s).'
                if delta > run.limits.pipeline_stale_days_error:
                    run.error(message)
                elif delta > run.limits.pipeline_stale_days_warning:
                    run.warning(message)
                elif delta > run.limits.pipeline_stale_days_pedantic:
                    run.pedantic(message)
                else:
                    run.info('Pipelines seem busy enough.')
                return

        run.warning('No successful pipelines in at least the last '
                    f'{run.limits.pipeline_backlog_count_max} runs.')

    except gitlab.GitlabListError as ex:
        run.error('Problem fetching pipelines, '
                  f'is this a production service project? Exception: {ex}')


def evaluate_commit_activity(run: LintReport) -> None:
    """
    Evaluates commit activity on the project referred to in the LintReport.

    Checks made:
    * Whether there are any commits
    * How recent they are

    Uses Thresholds.commit_stale_days_error, .commit_stale_days_warning, and
    .commit_stale_days_pedantic to evaluate.

    :param run: LintReport
    """
    try:
        # This could throw a GitlabListError from the list() method
        commits = run.proj.commits.list(per_page=1)

        if len(commits) == 0:
            run.error('No commits at all.')
        else:
            commit = commits[0]
            delta = get_delta_days(commit.committed_date)
            message = f'No commits for {delta} day(s).'

            if delta > run.limits.commit_stale_days_error:
                run.error(message)
            elif delta > run.limits.commit_stale_days_warning:
                run.warning(message)
            elif delta > run.limits.commit_stale_days_pedantic:
                run.pedantic(message)
            else:
                run.info('Commits seem busy enough.')

    except gitlab.GitlabListError as error:
        run.error(f'Problem fetching completed merge requests, {error}.')


def evaluate_completed_merges(run: LintReport) -> None:
    """
    TODO:

    :param run: LintReport
    """
    try:
        # Get the most recent merged MR
        merges = run.proj.mergerequests.list(state='merged',
                                             order_by='updated_at',
                                             sort='desc',
                                             per_page=1)
        if len(merges) == 0:
            run.error('No completed merge requests ever.')
        else:
            merged_at = merges[0].merged_at
            if not merged_at:
                merged_at = merges[0].updated_at
            delta = get_delta_days(merged_at)

            message = f'No completed merge requests for {delta} day(s).'

            if delta > run.limits.merge_stale_days_error:
                run.error(message)
            elif delta > run.limits.merge_stale_days_warning:
                run.warning(message)
            elif delta > run.limits.merge_stale_days_pedantic:
                run.pedantic(message)
            else:
                run.info('Completed merge requests show recent activity.')

    except gitlab.GitlabListError as error:
        run.error(f'Problem fetching completed merge requests, {error}.')


def evaluate_pending_merges(run: LintReport) -> None:
    """
    TODO:

    :param run: LintReport
    """
    try:
        # Ask for the oldest, ordering by updated_at
        merges = run.proj.mergerequests.list(state='opened',
                                             order_by='updated_at',
                                             sort='asc',
                                             all=True)
        if len(merges) == 0:
            run.info('No pending merge requests.')
        else:
            delta_old = get_delta_days(merges[0].created_at)
            delta_new = get_delta_days(merges[-1].created_at)

            message = f'{len(merges)} active Merge Requests, '
            message += f'the newest is {delta_new} day(s) old, '
            message += f'the oldest is {delta_old}.'

            if (delta_old > run.limits.pending_merge_oldest_error or
                    delta_new > run.limits.pending_merge_newest_error or
                    len(merges) > run.limits.pending_merge_max):
                run.error(message)
            elif delta_new > run.limits.pending_merge_newest_warning:
                run.warning(message)
            elif delta_new > run.limits.pending_merge_newest_pedantic:
                run.pedantic(message)
            else:
                run.info(message)

            future_stale_branches = 0
            for merge in merges:
                if not merge.should_remove_source_branch:
                    future_stale_branches += 1

            if future_stale_branches:
                run.warning(f'There are {future_stale_branches} pending merge '
                            'request(s) that do not have \'Delete source '
                            'branch when merged\' enabled.')

    except gitlab.GitlabListError as error:
        run.error(f'Problem fetching pending merge requests, {error}.')


def evaluate_branches_merged(run: LintReport, branches: list) -> None:
    """
    TODO:

    :param run: LintReport
    :param branches: list
    """
    merged_count = 0
    for branch in branches:
        # turns out, there are 'some' branches that don't have this field
        if hasattr(branch, 'merged') and branch.merged:
            merged_count += 1

    if merged_count == 0:
        run.info('No merged branches.')
    else:
        message = f'{merged_count} merged branches can be deleted.'

        if merged_count > run.limits.branch_merged_error:
            run.error(message)
        elif merged_count > run.limits.branch_merged_warning:
            run.warning(message)
        elif merged_count > run.limits.branch_merged_pedantic:
            run.pedantic(message)


def evaluate_branches_staleness(run: LintReport, branches: list) -> None:
    """
    TODO:

    :param run: LintReport
    :param branches: list
    """
    stale_count = 0
    # We just want to count up the number of branches whose latest commit
    # is over 'branch_stale_days' old. There's no stale/age available
    # in the query of the branches.list() so no choice but to iterate
    for branch in branches:
        delta = get_delta_days(branch.commit['committed_date'])
        if delta > Config.branch_stale_days:
            stale_count += 1
        else:
            break

        if stale_count == 1:
            LintReport.trace(f'Found oldest branch \'{branch.name}\' at '
                             f'{delta} day(s) old.')

    LintReport.trace(f'Found {stale_count} branch(es) over '
                     f'{Config.branch_stale_days} day(s) old.')

    message = (f'{stale_count} stale branch(es) have not been touched in more '
               f'than {Config.branch_stale_days} day(s).')

    if stale_count > run.limits.branch_stale_count_error:
        run.error(message)
    elif stale_count > run.limits.branch_stale_count_warning:
        run.error(message)
    elif stale_count > run.limits.branch_stale_count_pedantic:
        run.error(message)
    else:
        run.info(f'No stale branch(es) (over {Config.branch_stale_days} '
                 'day(s)).')


def evaluate_branches(run: LintReport) -> None:
    """
    TODO:

    :param run: LintReport
    """
    # there's no query for merged branches, so we have to get 'em all & count
    branches = run.proj.branches.list(all=True)

    # first, let's count and warn on the merged branches because these
    # should really be deleted.
    evaluate_branches_merged(run, branches)

    # next, let's look at the overall branch count and use that as a signal
    # for how much cognitive baggage is hanging in the repo.
    count = len(branches)

    if count > run.limits.branch_count_error:
        run.error(f'Too many branches, {count}; brains and systems hurt!')
    elif count > run.limits.branch_count_warning:
        run.warning(f'Quite a few branches, {count}; clean these up.')
    elif count > run.limits.branch_count_pedantic:
        run.pedantic(f'You\'re so close, clean up the last {count} branches!')
    elif count > 0:
        run.info(f'Good job, you have only {count} branches.')

    # now we can sort the branches by their recent commit date, this lets us
    # look for stale ones. Sort for the oldest first.
    branches.sort(key=lambda x: x.commit['committed_date'], reverse=False)

    evaluate_branches_staleness(run, branches)


def evaluate_default_branch(run: LintReport) -> None:
    """
    TODO:

    :param run: LintReport
    """
    if run.proj.default_branch != 'main':
        run.warning('Default branch is not \'main\','
                    f'currently called \'{run.proj.default_branch}\' instead.')


def evaluate_deployments(run: LintReport) -> None:
    """
    TODO:

    :param run: LintReport
    """
    # First, see if there are environments; if not, there can be no deployments
    environments = run.proj.environments.list(all=True)
    if len(environments) == 0:
        run.warning('No environments defined, so no deployments are tracked.')
        return

    LintReport.trace(f'Found {len(environments)}, evaluating deployments.')

    finished_after = Config.deployments_after.date()
    deployments = run.proj.deployments.list(updated_after=finished_after,
                                            as_list=False,
                                            sort='desc',
                                            all=True,
                                            status='success')

    if len(deployments) == 0:
        run.warning(f'No successful deployment(s) since {finished_after}.')

    count_per_env = {}
    for deployment in deployments:
        environment = deployment.environment['name']
        count_per_env[environment] = count_per_env.get(environment, 0) + 1

    run.info(f'Successful deployment(s) since {finished_after}, per env: '
             f'{count_per_env}.')


def evaluate_project(proj: Project) -> LintReport:
    """
    TODO:

    :param proj: Project, as a gitlab project object
    :return: The run object that contains the project being evaluated and an
    instance of the limits/thresholds to use, and into which all the results
    will be accumulated.
    :rtype: LintReport
    """
    run = LintReport(proj, limits=Thresholds())

    LintReport.trace(f'Evaluating {proj.path_with_namespace}.')

    try:
        if not evaluate_archive_status(run):
            evaluate_visibility(run)
            evaluate_project_settings(run)
            evaluate_description(run)
            evaluate_readme(run)
            evaluate_default_branch(run)
            evaluate_ci_config(run)
            evaluate_forked(run)
            evaluate_forks(run)
            evaluate_subprojects(run)
            evaluate_recent_activity(run)
            evaluate_commit_activity(run)
            evaluate_branches(run)
            evaluate_completed_merges(run)
            evaluate_pending_merges(run)
            evaluate_pipelines(run)
            evaluate_deployments(run)

    # We're catching Exception generally here because this is a tool that
    # iterates and evaluates rules over a number of entities. If one entity
    # triggers an exception due to unhandled data, we want to continue with
    # other entities in the list. We've evolved past the bad old days of stop
    # after one error (looking at you, Turbo Pascal). So...shut up, pylint...
    # pylint: disable=W0703
    except Exception as error:
        run.error(f'Internal Linter Exception, cannot continue: {error}.',
                  show_stack=True)
    # pylint: enable=W0703

    return run


# pylint: disable=W0511, C0302
# TODO: Damn this is a long module...delete this pylint after the breakup
# Also, tell pylint to ignore the to-do
# pylint: enable=W0511
# -----------------------------------------------------------------------------

def setup_argparse() -> ArgumentParser:
    """
    Describe all the arguments, creating an ArgumentParser object for the
    tool to use to crack the CLI arguments and run.

    :return: The ArgumentParser instance to use to crack the arguments.
    :rtype: ArgumentParser
    """
    parser = ArgumentParser(prog='gitlint',
                            description='Lint-like analysis for Gitlab repos')
    parser.add_argument('repo',
                        metavar='<repo_name>',
                        nargs='*',
                        help='The pathname of a repository to lint, '
                             'taking the form \'group/repo\'')
    parser.add_argument('-g', '--group',
                        metavar='<group_name>',
                        nargs='*',
                        help='The name of a group, all of whose projects will'
                             'be enumerated and linted. If more than one '
                             'group matches the (partial) name, then the '
                             'first match is used')
    parser.add_argument('--id',
                        metavar='<group_ID>',
                        type=int,
                        nargs='*',
                        help='The gitlab ID of a group, all of whose '
                             'projects will be enumerated and linted')
    parser.add_argument('--warn-as-error',
                        action='store_true',
                        help='Treats any warnings in the lint report as error '
                             'in terms of severity, and will send a non-zero '
                             'exit code')
    parser.add_argument('--token',
                        metavar='<token>',
                        help='Sets the gitlab access token. The token is '
                             'required either via this switch or by the '
                             '\'GITLINT_TOKEN\' env variable')
    parser.add_argument('--deployments-after',
                        metavar='<deployments_after>',
                        help='Sets the recent date after which to count '
                             'successful deployments; defaults to most '
                             'recent seven days, assumes midnight as time')
    spew_level = parser.add_mutually_exclusive_group()
    spew_level.add_argument('-e', '--error',
                            action='store_true',
                            help='Error mode evaluates only the most severe '
                                 'conditions, ignores everything of lower '
                                 'severity (warn, pedantic, info)')
    spew_level.add_argument('-w', '--warning',
                            action='store_true',
                            help='Warning mode evaluates moderately severe '
                                 'conditions, ignores everything of lower '
                                 'severity (pedantic, info)')
    spew_level.add_argument('-p', '--pedantic',
                            action='store_true',
                            help='Pedantic mode evaluates the most strict '
                                 'conditions')
    spew_level.add_argument('-i', '--info',
                            action='store_true',
                            help='Info mode also emits info messages about '
                                 '\'passing\' evaluations and rules')
    spew_level.add_argument('-v', '--verbose',
                            action='store_true',
                            help='Verbose mode emits detailed step-by-step '
                                 'tracing information, useful for debugging')
    parser.add_argument('--host',
                        metavar='<hostname>',
                        help='Host name of the gitlab server, prepends '
                             'https:// if needed.')
    parser.add_argument('--always-pass',
                        action='store_true',
                        help='Will evaluate and report but always return '
                             'a successful exit code')
    parser.add_argument('--no-sort',
                        action='store_true',
                        help='Disables sorting the diagnostic messages '
                             'by severity')
    parser.add_argument('--show-rule-id',
                        action='store_true',
                        help='Includes rule IDs (e.g. B001) in output strings'
                             '(not yet implemented)')

    return parser


def process_arguments() -> None:
    """
    Given the ArgumentParser, crack the command-line arguments and plug
    them into all the appropriate configuration and global settings in the
    Config class.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    process_gitlab_token(args)

    process_lint_level(args)
    LintReport.trace(f'Diagnostic level is \'{str(Config.lint_level)}\'.')

    Config.should_warn_as_error = args.warn_as_error
    if Config.should_warn_as_error:
        LintReport.trace('Warnings will be treated as errors.')

    process_gitlab_host(args)
    LintReport.trace(f'Gitlab host name is \'{Config.gitlab_host}\'.')

    Config.always_pass = args.always_pass
    Config.show_rule_id = args.show_rule_id
    Config.no_sort_output = args.no_sort

    if args.id:
        Config.group_ids = args.id

    if args.group:
        Config.group_names = args.group

    Config.projects = args.repo

    if not args.repo and not args.id and not args.group:
        parser.error('At least one of \'repo\', \'--id\', or '
                     '\'--group\' is required.')

    Config.deployments_after = datetime.now() + timedelta(days=-7)

    if args.deployments_after:
        try:
            Config.deployments_after = datetime.fromisoformat(
                    args.deployments_after)
        except ValueError:
            print('Failed to parse deployments_after argument, '
                  f'{args.deployments_after}; using \'today - 7\' '
                  'as the default instead.')


def process_lint_level(args: Namespace) -> None:
    """
    TODO:

    :param args:
    """
    if args.verbose:
        Config.lint_level = Severity.VERBOSE
    elif args.info:
        Config.lint_level = Severity.INFO
    elif args.pedantic:
        Config.lint_level = Severity.PEDANTIC
    elif args.error:
        Config.lint_level = Severity.ERROR
    else:
        Config.lint_level = Severity.WARNING


def process_gitlab_host(args: Namespace) -> None:
    """
    TODO:

    :param args:
    """
    if args.host and len(args.host) > 0:
        if not (args.host.startswith('http:') or
                args.host.startswith('https:')):
            Config.gitlab_host = 'https://' + args.host
        else:
            Config.gitlab_host = args.host


def process_gitlab_token(args: Namespace) -> None:
    """
    TODO:

    :param args:
    """
    if args.token and len(args.token):
        Config.gitlab_token = args.token
        LintReport.trace('Setting token from --token switch '
                         f'to {Config.obfuscated_token()}.')
    else:
        env_token = os.getenv('GITLINT_TOKEN')
        if env_token:
            Config.gitlab_token = env_token
            LintReport.trace('Setting token from GITLINT_TOKEN environment '
                             f'to {Config.obfuscated_token()}.')
        else:
            LintReport.trace('No token available, either with GITLINT_TOKEN '
                             'environment variable or --token switch.')
            fatal('No gitlab token provided.', os.EX_CONFIG)


# -----------------------------------------------------------------------------
# Some gitlab API helpers

def get_projects_for_group_name(lab: gitlab, target_name: str) -> \
        List[GroupProject]:
    """
    TODO:

    :param lab:
    :param target_name:
    :return: List of GroupProject objects
    :rtype: list
    """
    groups = lab.groups.list(search=target_name,
                             all_available=True)

    if len(groups) == 0:
        LintReport.trace(f'Found no groups matching \'{target_name}\'.')
        print(f'Cannot find group \'{target_name}\'.')
        return []

    group_id = groups[0].id
    group_name = groups[0].name

    if len(groups) > 1:
        LintReport.trace(f'Found {len(groups)} groups matching {target_name}, '
                         'using the first one: '
                         f'\'{group_name}\' (id {group_id}).')

    LintReport.trace(f'Getting projects from group {group_name} '
                     f'(id {group_id}).')
    projects = get_projects_for_group_id(lab, group_id)
    return projects


def get_projects_for_group_id(lab: gitlab, group_id: int) -> \
        List[GroupProject]:
    """
    TODO:

    :param lab:
    :param group_id:
    :return: List of GroupProject objects
    :rtype: list
    """
    projects = []
    try:
        group: Group = lab.groups.get(group_id)

        LintReport.trace(f'Getting projects from group {group.name} '
                         f'(id {group_id}).')
        group_projects = group.projects.list(all=True,
                                             order_by='last_activity_at',
                                             lazy=True,
                                             sort='desc')

        LintReport.trace(f'Adding {len(group_projects)} projects '
                         f'from group {group.name}.')
        for proj in group_projects:
            projects.append(proj)

    except gitlab.exceptions.GitlabGetError as ex:
        print(f'Cannot find group \'{group_id}\', error {ex}.')

    return projects


def get_file_from_project(proj: Project, file_path):
    """
    Returns a file object (or None, if error) from the HEAD of the default
    branch in the repo. The default branch is usually 'main'.
    """
    try:
        file = proj.files.raw(file_path=file_path, ref=proj.default_branch)
        LintReport.trace(f'Accessing \'{file_path}\' from {proj.name}.')
        return file
    except gitlab.GitlabGetError as _:
        LintReport.trace(
                f'Problem accessing \'{file_path}\' from {proj.name}.')
        return None


def convert_api_datetime(timestamp: str) -> datetime:
    """
    Python is mental in parsing standard timestamps. Worse, before 3.7,
    it could not even round-trip its own timestamp format.
    See https://bugs.python.org/issue31800

    :param timestamp: String that contains a standard ISO timestamp
    :return: The datetime value of that string, parsed correctly
    :rtype: datetime
    """
    return datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f%z')


def get_delta_days(timestamp: str) -> int:
    """
    TODO:

    :param timestamp:
    :return: Delta of current date to passed timestamp, in days
    :rtype: int
    """
    last = convert_api_datetime(timestamp).date()
    # Consider: Add ability to baseline the date checks to something other than today.
    # This would allow a run that looked at various aspects of aging,
    # recency, staleness from a given "reported on..." date instead of
    # just the date of the tool run.
    today = datetime.now().date()
    delta = today - last
    return delta.days


# -----------------------------------------------------------------------------

if __name__ == '__main__':
    MIN_MAJOR = 3
    MIN_MINOR = 7  # We need this version thanks to dumb datetime parsing

    if sys.version_info[0] < MIN_MAJOR or sys.version_info[1] < MIN_MINOR:
        fatal(f'{sys.argv[0]} requires at least '
              f'Python {MIN_MAJOR}.{MIN_MINOR}, but is running on '
              f'{sys.version_info.major}.{sys.version_info.minor}.',
              os.EX_SOFTWARE)

    process_arguments()
    sys.exit(main())
