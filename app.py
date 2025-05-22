import functools
import logging
import traceback
import sys
from flask import Flask, Blueprint, current_app, jsonify, request, redirect, abort
from io import BytesIO
# Grouped Flask imports for clarity
from flask import render_template, send_from_directory, url_for, send_file 
import os
import tempfile # Added for temporary cookie file handling
from pathlib import Path
from gevent.pywsgi import WSGIServer
import yt_dlp
from yt_dlp.version import __version__ as yt_dlp_version

if not hasattr(sys.stderr, 'isatty'):
  # In GAE it's not defined and we must monkeypatch
  sys.stderr.isatty = lambda: False

class SimpleYDL(yt_dlp.YoutubeDL):
  def __init__(self, *args, **kargs):
    super(SimpleYDL, self).__init__(*args, **kargs)
    self.add_default_info_extractors()

# --- MODIFIED get_videos function STARTS HERE ---
def get_videos(url, extra_params):
  '''
    Get a list with a dict for every video founded
    '''
  # --- START: TEMPORARY DEBUG LOG to check environment variable ---
  retrieved_cookie_content_from_env = os.environ.get('YOUTUBE_COOKIES_CONTENT')
  if retrieved_cookie_content_from_env:
      current_app.logger.info(f"DEBUG: YOUTUBE_COOKIES_CONTENT IS SET. Length: {len(retrieved_cookie_content_from_env)}. First 100 chars: '{retrieved_cookie_content_from_env[:100]}'")
  else:
      current_app.logger.warning("DEBUG: YOUTUBE_COOKIES_CONTENT IS NOT SET or is empty in the environment.")
  # --- END: TEMPORARY DEBUG LOG ---

  ydl_params = {
      'format': 'best',
      'cachedir': False,
      'verbose': False, # Kept as original
      'logger': current_app.logger.getChild('yt-dlp'),
      # Adding a User-Agent is a common practice and often helps with yt-dlp
      'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36'
  }
  
  temp_cookie_file_path = None # To store the path of a temporary cookie file, if created from env var

  # --- START: New Cookie Logic (prioritizing YOUTUBE_COOKIES_CONTENT environment variable) ---
  # cookie_content_env is already retrieved above for the debug log
  cookie_content_env = retrieved_cookie_content_from_env 
  if cookie_content_env:
      try:
          # Create a temporary file to store cookie content from the environment variable
          # delete=False is important because yt-dlp will open it by path. We manually delete it.
          with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8') as tmpfile:
              tmpfile.write(cookie_content_env)
              temp_cookie_file_path = tmpfile.name # Get the path of the temp file
          
          # Use this temporary cookie file for yt-dlp
          ydl_params['cookies'] = temp_cookie_file_path
          current_app.logger.info(f"Using cookies from YOUTUBE_COOKIES_CONTENT environment variable via temp file: {temp_cookie_file_path}")
      except Exception as e:
          current_app.logger.error(f"Failed to create or use temporary cookie file from YOUTUBE_COOKIES_CONTENT: {e} - {traceback.format_exc()}")
          # Clean up if temp_cookie_file_path was somehow set but an error occurred
          if temp_cookie_file_path and os.path.exists(temp_cookie_file_path):
              try:
                  os.remove(temp_cookie_file_path)
              except OSError:
                  pass # Ignore error during cleanup of partially created file
          temp_cookie_file_path = None # Ensure it's None if creation failed, so original logic can run
          # If this method fails, 'cookies' won't be in ydl_params, allowing fallback
  # --- END: New Cookie Logic ---

  # If cookies were NOT set by the environment variable method above (e.g., var not set or temp file failed),
  # then the original logic for Flask config cookies will run.
  if 'cookies' not in ydl_params:
      # *** This is your original block for getting cookies from Flask config ***
      cookies_path = current_app.config.get('/cookies.txt') # Your original key
      if cookies_path:
          # Your original assignment:
          # This path needs to be absolute or correctly relative to where the app is running 
          # (current working directory of the Gunicorn process) for yt-dlp to find it.
          ydl_params['cookies'] = cookies_path 
          current_app.logger.info(f"Using cookies from Flask config key '/cookies.txt' with path: {cookies_path}")
      # else: No logging in original if key not found, so kept as is.
          # current_app.logger.info("No cookie path found in Flask config under key '/cookies.txt'.")

  # Final check for logging if no cookie method was successful
  if 'cookies' not in ydl_params:
      current_app.logger.warning("No cookies configured via YOUTUBE_COOKIES_CONTENT or Flask config. YouTube may require authentication.")
  
  ydl_params.update(extra_params)
  ydl = SimpleYDL(ydl_params)
  
  res = None # Initialize res
  try:
      res = ydl.extract_info(url, download=False)
  finally:
      # Clean up the temporary cookie file ONLY if it was created from the environment variable
      if temp_cookie_file_path and os.path.exists(temp_cookie_file_path):
          try:
              os.remove(temp_cookie_file_path)
              current_app.logger.info(f"Removed temporary cookie file (from env var): {temp_cookie_file_path}")
          except OSError as e_remove:
              current_app.logger.error(f"Error removing temporary cookie file {temp_cookie_file_path}: {e_remove}")
  return res
# --- MODIFIED get_videos function ENDS HERE ---

def flatten_result(result):
  # Added safety for None result
  if result is None:
    current_app.logger.warning("flatten_result received None, returning empty list.")
    return []
  r_type = result.get('_type', 'video')
  if r_type == 'video':
    videos = [result]
  elif r_type == 'playlist':
    videos = []
    # Added safety check for result['entries'] being None or not existing, common in yt-dlp results
    if result.get('entries'):
        for entry in result['entries']:
            # Added safety check for entry being None
            if entry:
                videos.extend(flatten_result(entry))
  elif r_type == 'compat_list':
    videos = []
    # Added safety check for result['entries'] being None or not existing
    if result.get('entries'):
        for r_entry in result['entries']: # Renamed 'r' to 'r_entry' for clarity
            # Added safety check for r_entry being None
            if r_entry:
                videos.extend(flatten_result(r_entry))
  else: # Handle unrecognized types
    current_app.logger.warning(f"flatten_result encountered an unrecognized _type: {r_type}")
    videos = []
  return videos

api = Blueprint('api', __name__)

def route_api(subpath, *args, **kargs):
  return api.route('/api/' + subpath, *args, **kargs)

def set_access_control(f):
  @functools.wraps(f)
  def wrapper(*args, **kargs):
    response = f(*args, **kargs)
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response
  return wrapper

@api.errorhandler(yt_dlp.utils.DownloadError)
@api.errorhandler(yt_dlp.utils.ExtractorError)
def handle_youtube_dl_error(error):
  # Log the full traceback for yt-dlp errors
  current_app.logger.error(f"yt-dlp Download/Extractor Error: {str(error)}\n{traceback.format_exc()}")
  result = jsonify({'error': str(error)})
  result.status_code = 500
  return result

class WrongParameterTypeError(ValueError):
  def __init__(self, value, type, parameter):
    message = '"{}" expects a {}, got "{}"'.format(parameter, type, value)
    super(WrongParameterTypeError, self).__init__(message)

@api.errorhandler(WrongParameterTypeError)
def handle_wrong_parameter(error):
  current_app.logger.error(f"Wrong Parameter Type Error: {str(error)}\n{traceback.format_exc()}")
  result = jsonify({'error': str(error)})
  result.status_code = 400
  return result

@api.before_request
def block_on_user_agent():
  user_agent = request.user_agent.string
  forbidden_uas = current_app.config.get('FORBIDDEN_USER_AGENTS', [])
  if user_agent in forbidden_uas:
    abort(429)

def query_bool(value, name, default=None):
  if value is None:
    return default
  value = value.lower()
  if value == 'true':
    return True
  elif value == 'false':
    return False
  else:
    raise WrongParameterTypeError(value, 'bool', name)

ALLOWED_EXTRA_PARAMS = {
    'format': str,
    'playliststart': int,
    'playlistend': int,
    'playlist_items': str,
    'playlistreverse': bool,
    'matchtitle': str,
    'rejecttitle': str,
    'writesubtitles': bool,
    'writeautomaticsub': bool,
    'allsubtitles': bool,
    'subtitlesformat': str,
    'subtitleslangs': list,
}

def get_result():
  if 'url' not in request.args:
      current_app.logger.error("API request made without 'url' parameter.")
      abort(400, description="Missing 'url' parameter.")
  url = request.args['url']
  extra_params = {}
  for k, v in request.args.items():
    if k == 'url': # Skip 'url' itself
        continue
    if k in ALLOWED_EXTRA_PARAMS:
      convertf = ALLOWED_EXTRA_PARAMS[k]
      try:
        if convertf == bool:
            converted_v = query_bool(v, k)
        elif convertf == list:
            converted_v = v.split(',') # str.split returns a list of strings
        else:
            converted_v = convertf(v) # For int, str
        extra_params[k] = converted_v
      except WrongParameterTypeError: # Catch error from query_bool
          raise 
      except Exception as e:
          current_app.logger.error(f"Could not convert parameter '{k}' with value '{v}' using {convertf.__name__}: {e} - {traceback.format_exc()}")
          raise WrongParameterTypeError(v, convertf.__name__, k) # Re-raise as our defined error
    else:
        current_app.logger.debug(f"Ignoring unknown query parameter: {k}")
  return get_videos(url, extra_params)

@route_api('info')
@set_access_control
def info():
  try:
    result_data = get_result()
  except Exception as e: 
    # This will catch aborts from get_result or errors not handled by specific errorhandlers
    if isinstance(e, (yt_dlp.utils.DownloadError, yt_dlp.utils.ExtractorError, WrongParameterTypeError)):
        raise # Re-raise to be handled by the blueprint's error handlers
    current_app.logger.error(f"Unexpected error in /info route during get_result: {e}\n{traceback.format_exc()}")
    return jsonify({'error': f"An unexpected error occurred: {str(e)}"}), 500
  
  if result_data is None:
      current_app.logger.error(f"get_result() returned None for URL: {request.args.get('url')}. Cannot build response.")
      return jsonify({'error': 'Failed to retrieve video information.'}), 500

  url = request.args['url']
  key = 'info'
  if query_bool(request.args.get('flatten'), 'flatten', False):
    final_data = flatten_result(result_data) # Renamed for clarity
    key = 'videos'
  else:
    final_data = result_data
  
  response_payload = {
      'url': url,
      key: final_data,
  }
  return jsonify(response_payload)

@route_api('play')
def play():
  try:
    result_data = get_result()
  except Exception as e:
    if isinstance(e, (yt_dlp.utils.DownloadError, yt_dlp.utils.ExtractorError, WrongParameterTypeError)):
        raise
    current_app.logger.error(f"Unexpected error in /play route during get_result: {e}\n{traceback.format_exc()}")
    return jsonify({'error': f"An unexpected error occurred: {str(e)}"}), 500

  if result_data is None:
      current_app.logger.error("get_result() returned None for /play endpoint. Cannot redirect.")
      return jsonify({'error': 'Failed to retrieve video information for play.'}), 500
  
  flat_results = flatten_result(result_data) # Renamed for clarity
  if not flat_results or not isinstance(flat_results, list) or not flat_results[0] or 'url' not in flat_results[0]:
      current_app.logger.error(f"Could not extract a playable URL. Flattened result: {flat_results}")
      return jsonify({'error': 'Could not extract a playable URL from the video information.'}), 404
      
  return redirect(flat_results[0]['url'])

@route_api('extractors')
@set_access_control
def list_extractors():
  # Corrected to use yt_dlp.extractor.gen_extractors()
  ie_list = [{
      'name': ie.IE_NAME,
      'working': ie.working(),
  } for ie in yt_dlp.extractor.gen_extractors()]
  return jsonify(extractors=ie_list)

@route_api('version')
@set_access_control
def version():
  result = {
      'yt-dlp': yt_dlp_version,
      'yt-dlp-api-server': "0.3-debug-logging", # Indicate version
  }
  return jsonify(result)

app = Flask(__name__)
app.register_blueprint(api)

# Configuration loading
cfg_file_path_original = '../application.cfg' # Your original path
# Check if this file actually exists relative to app.py
# Example: if app.py is at /app/app.py, this looks for /application.cfg
# If app.py is at /app/src/app.py, this looks for /app/application.cfg
# Be sure this path is correct for your project structure.
# If it's not found, app.config will just be empty from this call (due to silent=True).
app.config.from_pyfile(cfg_file_path_original, silent=True)
if not app.config and os.path.exists(os.path.join(os.path.dirname(__file__), cfg_file_path_original)):
    current_app.logger.warning(f"Config file {cfg_file_path_original} was found but might not have loaded correctly or is empty.")
elif not os.path.exists(os.path.join(os.path.dirname(__file__), cfg_file_path_original)):
    current_app.logger.info(f"Config file {cfg_file_path_original} not found, using defaults or environment variables.")


@app.route('/api', methods=['GET']) 
def index():
  return "Hello, World!"


# --- Directory browsing/file serving part ---
home_directory = os.path.expanduser("~") # Not typically used on server environments like Railway
# app.instance_path is usually a folder named 'instance' next to your app package.
# For shared storage on Railway, consider /data persistent volume or specific path.
# This default might not be ideal for Railway.
shared_space = os.path.join(os.path.dirname(app.instance_path), os.sep, '') 
# A safer default for Railway if you want a 'downloads' dir in your project:
# shared_space = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'downloads')
# Or better, configure via an environment variable.
# if not os.path.exists(shared_space):
# try:
# os.makedirs(shared_space)
# app.logger.info(f"Created shared_space directory: {shared_space}")
# except OSError as e:
# app.logger.error(f"Could not create shared_space directory {shared_space}: {e}")


@app.route('/directory/')
@app.route('/directory/<path:folder>/')
def directory(folder=''):
    # Ensure shared_space is valid and exists before proceeding
    if not os.path.isdir(os.path.abspath(shared_space)):
        current_app.logger.error(f"Shared space directory '{shared_space}' does not exist or is not a directory.")
        abort(500, description="Server file storage is not configured correctly.")

    folder_path = os.path.join(shared_space, folder)
    abs_shared_space = os.path.abspath(shared_space)
    abs_folder_path = os.path.abspath(folder_path)
    if not abs_folder_path.startswith(abs_shared_space) or not os.path.isdir(abs_folder_path):
        current_app.logger.warning(f"Access denied or directory not found: {folder_path} (resolved to {abs_folder_path})")
        abort(404)
    try:
        files = get_file_list(abs_folder_path) 
    except OSError as e: 
        current_app.logger.error(f"Error listing directory {abs_folder_path}: {e}")
        abort(500)
    return render_template('directory.html', files=files, current_folder=folder) 

@app.route('/directory/<path:folder>/<filename>')
def download_file(folder, filename):
    if not os.path.isdir(os.path.abspath(shared_space)):
        current_app.logger.error(f"Shared space directory '{shared_space}' does not exist for download.")
        abort(500, description="Server file storage is not configured correctly.")

    folder_path = os.path.join(shared_space, folder)
    abs_shared_space = os.path.abspath(shared_space)
    abs_file_path = os.path.abspath(os.path.join(folder_path, filename))
    if not abs_file_path.startswith(abs_shared_space) or not os.path.isfile(abs_file_path):
        current_app.logger.warning(f"Access denied or file not found for download: {os.path.join(folder, filename)} (resolved to {abs_file_path})")
        abort(404)
    return send_from_directory(os.path.abspath(folder_path), filename, as_attachment=True)

def get_file_list(folder_path_abs): # Expects absolute path
    items = []
    if not os.path.isdir(folder_path_abs):
        current_app.logger.error(f"get_file_list called with non-directory: {folder_path_abs}")
        raise OSError(f"Not a directory: {folder_path_abs}")

    for item in os.listdir(folder_path_abs):
        item_path = os.path.join(folder_path_abs, item)
        if os.path.isfile(item_path):
            items.append({'name': item, 'type': 'file'})
        elif os.path.isdir(item_path):
            items.append({'name': item, 'type': 'folder'})
    return items

if __name__ == '__main__':
  # --- START: Enhanced Logging Configuration ---
  # Configure basic logging first (good for non-Flask specific logs from other libraries)
  # Output to stdout so Gunicorn/Railway can capture it.
  logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')

  # Explicitly set Flask's app logger level.
  # This needs to happen AFTER `app = Flask(__name__)` is defined.
  # Get FLASK_LOG_LEVEL from environment, then app.config, default to INFO.
  flask_log_level_str = os.environ.get('FLASK_LOG_LEVEL', app.config.get('LOG_LEVEL', 'INFO')).upper()
  flask_log_level = getattr(logging, flask_log_level_str, logging.INFO)
  
  app.logger.setLevel(flask_log_level)
  
  # Ensure Flask's logger has a handler that outputs to stdout if it doesn't already.
  # Gunicorn typically sets up its own handlers that capture Flask's default logger output,
  # but this makes it more robust.
  if not app.logger.handlers:
      stdout_handler = logging.StreamHandler(sys.stdout)
      # Use a formatter that matches the basicConfig or is suitable for production.
      formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
      stdout_handler.setFormatter(formatter)
      app.logger.addHandler(stdout_handler)
      app.logger.propagate = False # Prevent duplicate logs if Gunicorn also adds a handler to root.
  
  app.logger.info(f"Flask app logger initialized. Effective level: {logging.getLevelName(app.logger.getEffectiveLevel())}")
  # --- END: Enhanced Logging Configuration ---

  app.config["CACHE_TYPE"] = "null" 
  
  port = int(os.environ.get('PORT', 5000))
  host = '0.0.0.0'
  
  app.logger.info(f"Starting WSGIServer on {host}:{port}")
  http_server = WSGIServer((host, port), app)
  try:
    http_server.serve_forever()
  except KeyboardInterrupt:
    app.logger.info("Server shutting down.")
