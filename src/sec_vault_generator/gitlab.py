from sec_vault_generator.globals import *
from sec_vault_generator.exceptions import *
from functools import wraps
from copy import deepcopy
import requests

# NOTE: Usage notes below.
'''
# Creating API Calls

## The call Decorator

This decorator handles repetitive code.

Arguments:

    - path: The GitLab URL path that will be requested.
    - paginate: A boolean that determines if respones should be
        paginated, causing the method will behave as a generator.
    - rest_params: A dictionary that specifies the valid types
        for a given rest parameter.

# Making Calls

## Passing Standard Params and Data to API Calls

REST parameters aside, all data and parameters are passed directly
to the requests sec_vault_generatorrary for handling.

## Passing Arguments to REST Parameters

When making calls to Session objects, it will likely be necessary
to pass arguments to REST parameters within the URI. This is
achieved by passing a "rest_params" keyword argument to the method.

Example:

session.revokeProjectAccessToken(
    rest_params={
        'project_id': 7,
        'token_id': 33})
'''

API_BASE = GITLAB_API_URL

class RTypes:

    project_id = user_id = token_id = key_id = int

    @classmethod
    def getTypes(cls, *handles):
        
        invalid_handles, types = [], {}
        for handle in handles:

            if not type(handle) == str:
                invalid_handles.append('{}: handle must be a string, got {}',
                    str(handle), type(handle))
            elif not hasattr(cls, handle):
                invalid_handles.append('{}: Unknown handle.', handle)
            else:
                types[handle] = getattr(cls, handle)

        if invalid_handles:

            raise ValueError(
                'Invalid type handles supplied: '
                f'{" -- ".join(invalid_handles)}')

def checkResponse(resp):

    if resp.status_code == 403:

        # =======================
        # INSUFFICIENT PRIVILEGES
        # =======================

        raise InsufficientPrivileges(
            'Insufficient privileges for token: '
            f'{resp.json()}')

    elif resp.status_code == 204:

        # ===================
        # NO CONTENT RETURNED
        # ===================

        setattr(resp, 'json', lambda: {})

    elif resp.status_code > 400:

        raise RequestError(
            f'Response status code {resp.status_code} indicates an error: '
            'https://docs.gitlab.com/ee/api/#status-codes')

    return resp

def getNextURL(resp):
    return resp.links.get('next', {}) \
        .get('url', None)

def prepareParams(rest_params, rest_args, kwargs) -> (dict, dict,):
    '''Initialize and return the parameters.
    '''

    # Ensure that a dictionary is always supplied to
    # rest_params
    rest_params = rest_params if rest_params else {}
    rest_args = rest_args if rest_args else {}

    # ================================
    # PERFORM CHECKS ON REST ARGUMENTS
    # ================================

    value_errors = {}

    for name, types in rest_params.items():

        # =======================================
        # ENSURE THAT REST ARGUMENTS ARE SUPPLIED
        # =======================================

        if not name in rest_args:

            value_errors[name] = (
                f'{name}: Requires a value of the following types > '
                f'{types}')

        else:

            # =====================
            # ENFORCE TYPE CHECKING
            # =====================

            if not isinstance(rest_args[name], types):

                value_errors[name] = (
                    f'{name}: Requires a value of the following '
                    f'types > {types}. Got {type(rest_args["name"])}')

    if value_errors:

        # ==================
        # RAISE AN EXCEPTION
        # ==================

        msg = ''

        for name, error in value_errors.items():
            if not msg:
                msg = error
            else:
                msg += ' ' + error

        raise ValueError(msg)

    # Ensure a dictionary is always supplied to the
    # params value within kwargs.
    if not kwargs.get('params', None):
        kwargs['params']={}

    return rest_args, kwargs

def call(path, paginate=False, rest_params=None):
    '''Wrap a Session method such that it will receive a URI value
    with updated REST parameters, followed by making the request
    and returning/yielding the response from the Session object.

    Args:
        path: String path for the API call.
        paginate: Determines if this decorator should behave as
            a generator.
    '''

    # Ensure path is prefixed with a slash
    if not path[0] == '/':
        path = '/'+path

    _rest_params = rest_params if rest_params else {}

    def outer(method):

        if paginate:

            # ============
            # YIELDS PAGES
            # ============

            @wraps(method)
            def wrapper(obj, rest_params=None, *args, **kwargs):
    
                rest_params, kwargs = prepareParams(_rest_params,
                    rest_params, kwargs)

                # Get the initial response
                uri = API_BASE+path.format(**rest_params) 
                resp = checkResponse(method(obj, uri, *args, **kwargs))

                # yield the initial response
                if obj.json_output:
                    yield resp.json()
                else:
                    yield resp
    
                # get the next url from the links within the response
                # object
                next_url = getNextURL(resp)
    
                # yield each subsequent request
                while next_url is not None:

                    resp = obj.get(next_url)

                    if obj.json_output:
                        yield resp.json()
                    else:
                        yield resp

                    next_url = getNextURL(resp)

        else:

            # ============================
            # RETURNS INDIVIDUAL RESPONSES
            # ============================

            @wraps(method)
            def wrapper(obj, rest_params=None,
                    *args, **kwargs):
    
                rest_params, kwargs = prepareParams(_rest_params,
                        rest_params,
                        kwargs)
    
                # Call the method and return the response
                resp = checkResponse(method(obj,
                        API_BASE+path.format(**rest_params),
                        *args, **kwargs))

                if obj.json_output:
                    return resp.json()
                else:
                    return resp
    
        return wrapper

    return outer

class Session(requests.Session):

    def __init__(self, token, json_output=False, *args, **kwargs):
        '''Initialize a Session object by accepting a token and
        binding it as an instance variable.

        Args:
            token: Authorization token used to authenticate to the
                GitLab API.
            json_output: Determines if all output from API calls should
                be returned as JSON objects instead of a response object.

        Notes:
            - The last_resp attribute will always hold the most recent
              response object.
        '''

        super().__init__(*args, **kwargs)
        self.token = token
        self.json_output = json_output
        self.last_resp = None
        self.headers.update({'PRIVATE-TOKEN': self.token})

    def request(self, url, *args, **kwargs):
        '''Override the request method such that the proper authorization
        header is always sent to the API.
        '''

        # Make the request
        self.last_resp = super().request(url, *args, **kwargs)
        return self.last_resp

    def search(self, uri, *args, **kwargs):
        '''Query GitLab's search endpoint.

        Notes:
            - https://docs.gitlab.com/ee/api/search.html
        '''

        return self.get(uri, *args, **kwarg)

    def findProject(self, repo_name, repo_https_url) -> dict:
        '''Find a project based on repository name while verifying
        that the proper project has been identified by comparing
        the "http_url_to_repo" member to repo_https_url.

        Args:
            repo_name: Repo name to search for.
            repo_https_url: Full URL to the repository, for validation.

        Returns:
            Dictionary object representing the project, as returned
            by the GitLab API.

        Notes:
            - Unlike other API calls, this call will always return
              a dict object.
        '''

        if not repo_https_url.endswith('.git'):
            repo_https_url += '.git'

        json_output = self.json_output
        self.json_output = True
        output = {}

        for page in self.iterProjects(params={'search':repo_name}):

            for proj in page:
                if proj['http_url_to_repo'] == repo_https_url:
                    output = proj
                    break

        self.json_output = json_output

        return output

    @call(path='/projects/{project_id}/access_tokens/{token_id}',
            rest_params=RTypes.getTypes('project_id', 'token_id'))
    def revokeProjectAccessToken(self, uri, *args, **kwargs):
        '''Revoke a project access token.

        Notes:
            - https://docs.gitlab.com/ee/api/resource_access_tokens.html#revoke-a-project-access-token
        '''

        return self.delete(uri, *args, **kwargs)

    @call(path='/users', paginate=True)
    def iterAllUsers(self, uri, *args, **kwargs):
        '''Generator that iterates over all GitLab users.

        Notes:
            - https://docs.gitlab.com/ee/api/users.html#list-users
        '''

        return self.get(uri, *args, **kwargs)

    @call(path='/projects/{project_id}/access_tokens',
            paginate=True,
            rest_params=RTypes.getTypes('project_id'))
    def iterProjectAccessTokens(self, uri, *args, **kwargs):
        '''Generator that iterates over all Project Access Tokens for
        a given GitLab project.

        Notes:
            - https://docs.gitlab.com/ee/api/resource_access_tokens.html#list-project-access-tokens
        '''

        return self.get(uri, *args, **kwargs)

    @call(path='/deploy_keys', paginate=True)
    def iterDeployKeys(self, uri, *args, **kwargs):
        '''Paginate over all deploy keys configured in GitLab.

        Notes:
            - https://docs.gitlab.com/ee/api/deploy_keys.html#list-all-deploy-keys
        '''

        return self.get(uri, *args, **kwargs)

    @call(path='/projects/{project_id}/deploy_keys',
            paginate=True, rest_params=RTypes.getTypes('project_id'))
    def iterProjectDeployKeys(self, uri, *args, **kwargs):
        '''
        Notes:
            - https://docs.gitlab.com/ee/api/deploy_keys.html#list-project-deploy-keys
        '''

        return self.get(uri, *args, **kwargs)

    @call(path='/projects/{project_id}/deploy_keys/{key_id}',
            rest_params=RTypes.getTypes('project_id', 'key_id'))
    def updateProjectDeployKey(self, uri, *args, **kwargs):
        '''
        Notes:
            - https://docs.gitlab.com/ee/api/deploy_keys.html#update-deploy-key
        '''

        return self.put(uri, *args, **kwargs)

    @call(path='/projects/{project_id}/deploy_keys/{key_id}',
            rest_params=RTypes.getTypes('project_id', 'key_id'))
    def deleteProjectDeployKey(self, uri, *args, **kwargs):
        '''
        Notes:
            - https://docs.gitlab.com/ee/api/deploy_keys.html#update-deploy-key
        '''

        return self.delete(uri, *args, **kwargs)

    @call(path='/projects/{project_id}',
            rest_params=RTypes.getTypes('project_id', 'key_id'))
    def getProject(self, uri, *args, **kwargs):
        '''Get an individual project from the GitLab API.

        Notes:
            - https://docs.gitlab.com/ee/api/projects.html#get-single-project
        '''
        
        return self.get(uri, *args, **kwargs)

    @call(path='/projects/{project_id}/repository/tree',
            rest_params=RTypes.getTypes('project_id'), paginate=True)
    def iterProjectRepoTree(self, uri, *args, **kwargs):
        '''Get a list of files from the repository.

        Notes:
            - https://docs.gitlab.com/ee/api/repositories.html#list-repository-tree
        '''

        return self.get(uri, *args, **kwargs)

    @call(path='/groups', paginate=True)
    def iterGroups(self, uri, *args, **kwargs):
        '''Generator that iterates over all GitLab groups.
        Notes:
            - https://docs.gitlab.com/ee/api/groups.html#list-groups
        '''

        return self.get(uri, *args, **kwargs)

    @call(path='/projects/{project_id}/share',
        rest_params=RTypes.getTypes('project_id'))
    def shareProjectWithGroup(self, uri, *args, **kwargs):
        '''
        Notes:
            - https://docs.gitlab.com/ee/api/projects.html#share-project-with-group
        '''

        return self.post(uri, *args, **kwargs)

    @call(path='/projects/{project_id}/members',
        rest_params=RTypes.getTypes('project_id'))
    def addMemberToProject(self, uri, *args, **kwargs):
        '''
        Note:
            - https://docs.gitlab.com/ee/api/members.html#add-a-member-to-a-group-or-project
        '''

        return self.post(uri, *args, **kwargs)

    @call(path='/projects/{project_id}/access_tokens',
        rest_params=RTypes.getTypes('project_id'))
    def getProjectAccesstokens(self, uri, *args, **kwargs):
        '''Get all access tokens configured for a project.

        Notes:
            - https://docs.gitlab.com/ee/api/resource_access_tokens.html#list-project-access-tokens
        '''

        return self.get(uri, *args, **kwargs)

    @call(path='/projects', paginate=True)
    def iterProjects(self, uri, *args, **kwargs):
        '''Return a generator that iterates through each project in
        the GitLab instance.

        Notes:
            - https://docs.gitlab.com/ee/api/projects.html#list-all-projects
        '''

        return self.get(uri, *args, **kwargs)

    @call(path='/projects/{project_id}/members', paginate=True,
        rest_params=RTypes.getTypes('project_id'))
    def iterProjectMembers(self, uri, *args, **kwargs):
        '''Return a generateor that iterates over each member of the
        project identified by the project_id REST parameter.

        Notes:
            - This does not return inhertied group members.
            - https://docs.gitlab.com/ee/api/members.html#list-all-members-of-a-group-or-project
        '''

        return self.get(uri, *args, **kwargs)

    @call(path='/projects/{project_id}/members/all', paginate=True,
        rest_params=RTypes.getTypes('project_id'))
    def iterAllProjectMembers(self, uri, *args, **kwargs):
        '''Return a generateor that iterates over each member of the
        project identified by the project_id REST parameter.

        Notes:
            - This differs from iterProjectMembers by including inherited
                group members as well.
            - https://docs.gitlab.com/ee/api/members.html#list-all-members-of-a-group-or-project
        '''

        return self.get(uri, *args, **kwargs)

    @call(path='/projects/{project_id}/members/{user_id}',
        rest_params=RTypes.getTypes('project_id', 'user_id'))
    def updateProjectMember(self, uri, *args, **kwargs):
        '''
        Notes:
            - https://docs.gitlab.com/ee/api/members.html#edit-a-member-of-a-group-or-project
        '''

        return self.put(uri, *args, **kwargs)
