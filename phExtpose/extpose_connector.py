#!/usr/bin/python

""" Connector for working with Extpose """


import argparse
import getpass
import json

# Phantom App imports
import phantom.app as phantom  # pylint: disable=import-error
from phantom.base_connector import BaseConnector  # pylint: disable=import-error
from phantom.action_result import ActionResult  # pylint: disable=import-error

# Usage of the consts file is recommended
# from extpose_consts import *
import requests
from bs4 import BeautifulSoup


class RetVal(tuple):
    """return value typing?"""

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ExtposeConnector(BaseConnector):
    """connector class"""

    def __init__(self):
        # Call the BaseConnectors init first
        super(ExtposeConnector, self).__init__()

        self._state = None
        self.request_timeout = 30

        self.print_progress_message = False

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = "https://extpose.com"

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ),
            None,
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception:  # pylint: disable=broad-except
            error_text = "Cannot parse error details"

        message = f"Status Code: {status_code}. Data from server:\n{error_text}\n"

        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):
        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as error:  # pylint: disable=broad-except
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Unable to parse JSON response. Error: {error}",
                ),
                None,
            )

        # Please specify the status codes here
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        cleaned_text = response.text.replace("{", "{{").replace("}", "}}")
        # You should process the error returned in the json
        message = f"Error from server. Status Code: {response.status_code} Data from server: {cleaned_text}"  # noqa: E501

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": response.status_code})
            action_result.add_debug_data({"r_text": response.text})
            action_result.add_debug_data({"r_headers": response.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in response.headers.get("Content-Type", ""):
            return self._process_json_response(response, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in response.headers.get("Content-Type", ""):
            return self._process_html_response(response, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_response(response, action_result)

        cleaned_text = response.text.replace("{", "{{").replace("}", "}}")
        # everything else is actually an error at this point
        message = f"Can't process response from server. Status Code: {response.status_code} Data from server: {cleaned_text}"

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, f"Invalid method: {method}"
                ),
                resp_json,
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        if "timeout" in kwargs:
            timeout = kwargs["timeout"]
            del kwargs["timeout"]
        else:
            timeout = self.request_timeout

        try:
            response = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get("verify_server_cert", False),
                timeout=timeout**kwargs,
            )
        except Exception as error:  # pylint: disable=broad-except
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, f"Error Connecting to server. Details: {error}"
                ),
                resp_json,
            )

        return self._process_response(response, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")
        # make rest call
        try:
            ret_val, response = self._make_rest_call(
                "/", action_result, params=None, headers=None
            )

            response.raise_for_status()
        except Exception as error: #pylint: disable=broad-except
            return action_result.set_status(phantom.APP_ERROR, f"Failed to connect: {error}")

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            # return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_get_file(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            f"In action handler for: {self.get_action_identifier()}"
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        crx_id = param["crx_id"]

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call(
            f"/download/{crx_id}", action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            # return action_result.get_status()
            pass

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary['num_data'] = len(action_result['data'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        # return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def handle_action(self, param):
        """ action handler """
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "get_file":
            ret_val = self._handle_get_file(param)

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def initialize(self):
        """Load the state in initialize, use it to store data
        that needs to be accessed across actions"""
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        # Access values in asset config by the name

        # Required values can be accessed directly
        # required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        # optional_config_name = config.get('optional_config_name')

        self._base_url = config.get("base_url")

        return phantom.APP_SUCCESS

    def finalize(self):
        """Save the state, this data is saved across actions and app upgrades"""
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    """ main function """
    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = ExtposeConnector.base() + "/login"

            print("Accessing the Login page")
            response = requests.get(login_url, verify=False, timeout=30)
            csrftoken = response.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            response2 = requests.post(
                login_url, verify=False, data=data, headers=headers, timeout=30
            )
            session_id = response2.cookies["sessionid"]
        except Exception as error:  # pylint: disable=broad-except
            print(f"Unable to get session id from the platform. Error: {error}")
            exit(1)

    with open(args.input_test_json, encoding="utf-8") as file_handle:
        in_json = json.load(file_handle)
        print(json.dumps(in_json, indent=4, default=str))

        connector = ExtposeConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"]) # noqa: W0212, pylint: disable=W0212

        ret_val = connector._handle_action(json.dumps(in_json), None) # noqa: W0212, pylint: disable=W0212
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
