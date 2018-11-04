import json

# Try python 2 and then python 3
try:
  from urllib2 import HTTPError, URLError
except ImportError:
  from urllib.error import HTTPError, URLError

from traceback import format_exc


class RematchException(Exception):
  message = ""

  def __init__(self, **kwargs):
    super(RematchException, self).__init__()
    self._kwargs = kwargs

  def __str__(self):
    kwarg_str = ", ".join("{} = {}".format(k, v)
                          for k, v in self._kwargs.items())
    return "<{}: {}. args: {}>".format(self.__class__, self.message, kwarg_str)


class UnsavedIdb(RematchException):
  message = ("You mast save the IDB before uploading it to the database, "
             "please save and try again")


class QueryException(RematchException):
  message = ("Local error has occured! please report a reproducable bug if "
             "this issue persists")


class UnknownObjectReferenceException(QueryException):
  message = ("An object unknown to the server was referenced in a request. "
             "Please make sure you're logged in to the correct server, and "
             "that the object wasn't deliberately removed. Please report a "
             "reproducable bug if this issue persists")


class ConnectionException(QueryException):
  message = ("Can't connect to the server. Either your network connection is "
             "broken or the server is momentarily unavailable.")


class ServerException(QueryException):
  message = ("opps! we had a server error error. If this problem persists "
             "please report this issue.")


class AuthenticationException(RematchException):
  message = ("Failed authentication check on server. Please verify your "
             "credentials and try again")


class NotFoundException(QueryException):
  message = ("Asset not found. This could be either a plugin error or a "
             "server error.")


class InputErrorException(QueryException):
  message = ("An input error detected by the server, please adjust provided "
             "input and retry again. Please report a reproducable bug if "
             "this issue persists.")

  def errors(self):
    return self._kwargs['response'].items()


def factory(ex):
  original_tb = format_exc()

  if isinstance(ex, HTTPError):
    response_text = ex.read()
    try:
      response = json.loads(response_text)
    except Exception:
      response = response_text
    ex_cls = None
    if ex.code == 500:
      ex_cls = ServerException
    elif ex.code == 401:
      ex_cls = AuthenticationException
    elif ex.code == 404:
      ex_cls = NotFoundException
    elif ex.code == 400:
      ex_cls = handle_400(response)

    if ex_cls is not None:
      raise ex_cls(response=response, code=ex.code)
  elif isinstance(ex, URLError):
    raise ConnectionException(reason=ex.reason)

  raise Exception("Couldn't factor an exception: {}".format(original_tb))


def handle_400(resp):
  if isinstance(resp, dict):
    for errors in resp.values():
      if any("Invalid pk" in error for error in errors):
        return UnknownObjectReferenceException
    return InputErrorException
  else:
    return QueryException
