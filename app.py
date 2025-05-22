import functools
import logging
import traceback
import sys
from flask import Flask, Blueprint, current_app, jsonify, request, redirect, abort
from io import BytesIO
from flask import render_template, send_from_directory, url_for,send_file # Removed jsonify, request from here as already imported
import os
import tempfile
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
    retrieved_cookie_content_from_env = os.environ.get('YOUTUBE_COOKIES_CONTENT')
    if retrieved_cookie_content_from_env:
        current_app.logger.info(f"DEBUG (in get_videos): YOUTUBE_COOKIES_CONTENT IS SET. Length: {len(retrieved_cookie_content_from_env)}. First 100 chars: '{retrieved_cookie_content_from_env[:100]}'")
    else:
        current_app.logger.warning("DEBUG (in get_videos): YOUTUBE_COOKIES_CONTENT IS NOT SET or is empty in the environment.")

    ydl_params = {
        'format': 'best',
        'cachedir': False,
        'verbose': current_app.logger.level == logging.DEBUG, # Set verbose based on logger level
        'logger': current_app.logger.getChild('yt-dlp'),
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36'
    }
  
    temp_cookie_file_path = None 
  
    if retrieved_cookie_content_from_env:
        try:
            # Create a temporary file to store the cookie content
            # delete=False is important because yt-dlp needs to open it by path
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8') as tmpfile:
                tmpfile.write(retrieved_cookie_content_from_env)
                temp_cookie_file_path = tmpfile.name
            
            # --- MODIFICATION: Use 'cookies' option, not 'cookiesfrombrowser' ---
            ydl_params['cookies'] = temp_cookie_file_path 
            current_app.logger.info(f"Using 'cookies' option with temporary cookie file: {temp_cookie_file_path}")
            # --- END MODIFICATION ---
            
        except Exception as e:
            current_app.logger.error(f"Failed to create or use temporary cookie file: {e} - {traceback.format_exc()}")
            if temp_cookie_file_path and os.path.exists(temp_cookie_file_path):
                try: os.remove(temp_cookie_file_path)
                except OSError: pass 
            temp_cookie_file_path = None # Ensure it's None if creation failed
    
    # Fallback to a configured cookie file path if the environment variable method wasn't used or failed
    # Note: The original 'cookies_path = current_app.config.get('/cookies.txt')' was problematic.
    # Using an absolute path like '/cookies.txt' is unlikely to work in Railway.
    # It's better to use a relative path or another env var for a persistent cookie file if needed.
    # For now, we'll prioritize the YOUTUBE_COOKIES_CONTENT env var.
    if 'cookies' not in ydl_params:
        # Example of how you might configure a fallback path via app.config
        # In your application.cfg or environment variables: COOKIES_FILE_PATH = 'path/to/your/cookies.txt'
        configured_cookie_file = current_app.config.get('COOKIES_FILE_PATH')
        if configured_cookie_file:
            if os.path.exists(configured_cookie_file):
                ydl_params['cookies'] = configured_cookie_file
                current_app.logger.info(f"Using 'cookies' (fallback) from Flask config 'COOKIES_FILE_PATH': {configured_cookie_file}")
            else:
                current_app.logger.warning(f"Cookies file specified in 'COOKIES_FILE_PATH' ({configured_cookie_file}) not found.")
        else:
             current_app.logger.info("No YOUTUBE_COOKIES_CONTENT env var and no COOKIES_FILE_PATH in config. Proceeding without cookies.")
  
    if 'cookies' not in ydl_params :
        current_app.logger.warning("No cookies configured for yt-dlp.")
  
    current_app.logger.info(f"yt-dlp verbose initial state: {ydl_params.get('verbose')}")
    ydl_params.update(extra_params) 
    # If 'verbose' is in extra_params, it will override the initial setting.
    # This is fine, allowing API users to control verbosity.
    current_app.logger.info(f"Final yt-dlp verbose state after extra_params.update: {ydl_params.get('verbose')}")
    
    # Log final ydl_params, redacting sensitive info if necessary (though cookie file path isn't content)
    loggable_params = {k: v for k, v in ydl_params.items()}
    if 'cookies' in loggable_params:
      loggable_params['cookies'] = f"[path_to_cookie_file: {loggable_params['cookies']}]" # Don't log content
    current_app.logger.debug(f"Final ydl_params for yt-dlp: {loggable_params}")

    ydl = SimpleYDL(ydl_params)
    res = None 
    try:
        res = ydl.extract_info(url, download=False)
    except Exception as e:
        current_app.logger.error(f"Error during yt-dlp extract_info: {e}")
        # Re-raise the exception so it can be handled by Flask error handlers
        raise
    finally:
        # Clean up the temporary cookie file if it was created from the environment variable
        if temp_cookie_file_path and os.path.exists(temp_cookie_file_path):
            try:
                os.remove(temp_cookie_file_path)
                current_app.logger.info(f"Removed temporary cookie file: {temp_cookie_file_path}")
            except OSError as e_remove:
                current_app.logger.error(f"Error removing temporary cookie file {temp_cookie_file_path}: {e_remove}")
    return res
# --- MODIFIED get_videos function ENDS HERE ---

# ... (rest of your app.py code remains the same) ...

def flatten_result(result):
  if result is None:
    current_app.logger.warning("flatten_result received None, returning empty list.")
    return []
  r_type = result.get('_type', 'video')
  if r_type == 'video': videos = [result]
  elif r_type == 'playlist':
    videos = []
    if result.get('entries'):
        for entry in result['entries']:
            if entry: videos.extend(flatten_result(entry))
  elif r_type == 'compat_list':
    videos = []
    if result.get('entries'):
        for r_entry in result['entries']:
            if r_entry: videos.extend(flatten_result(r_entry))
  else:
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
  # Log the full traceback for server-side debugging
  current_app.logger.error(f"yt-dlp Download/Extractor Error: {str(error)}\n{traceback.format_exc()}")
  # Provide a generic error message to the client
  # Sometimes error messages can contain parts of the URL or other info not ideal for public display
  # Extract a safe error message if possible, or use a generic one
  public_error_message = "A download or extraction error occurred with the video provider."
  if hasattr(error, 'exc_info') and error.exc_info and len(error.exc_info) > 1:
      # Try to get the original error message if it's simpler
      original_error = error.exc_info[1]
      if "is not a valid URL" in str(original_error) or "Unsupported URL" in str(original_error):
          public_error_message = str(original_error)
      elif "Private video" in str(original_error) or "Video unavailable" in str(original_error):
          public_error_message = str(original_error)
  elif "ERROR:" in str(error): # yt-dlp often prefixes its own errors with ERROR:
      public_error_message = str(error).split('ERROR:', 1)[-1].strip()


  result = jsonify({'error': public_error_message})
  result.status_code = 500 # Internal Server Error or Bad Gateway might be appropriate
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
  if user_agent in forbidden_uas: abort(429)

def query_bool(value, name, default=None):
  if value is None: return default
  value = value.lower()
  if value == 'true': return True
  elif value == 'false': return False
  else: raise WrongParameterTypeError(value, 'bool', name)

ALLOWED_EXTRA_PARAMS = {
    'format': str, 'playliststart': int, 'playlistend': int, 'playlist_items': str,
    'playlistreverse': bool, 'matchtitle': str, 'rejecttitle': str, 'writesubtitles': bool,
    'writeautomaticsub': bool, 'allsubtitles': bool, 'subtitlesformat': str, 'subtitleslangs': list,
    'verbose': bool # Allow 'verbose' to be passed as an API param
}

def get_result():
  if 'url' not in request.args:
      current_app.logger.error("API request made without 'url' parameter.")
      abort(400, description="Missing 'url' parameter.")
  url = request.args['url']
  extra_params = {}
  for k, v in request.args.items():
    if k == 'url': continue
    if k in ALLOWED_EXTRA_PARAMS:
      convertf = ALLOWED_EXTRA_PARAMS[k]
      try:
        if convertf == bool: converted_v = query_bool(v, k)
        elif convertf == list: converted_v = v.split(',')
        else: converted_v = convertf(v)
        extra_params[k] = converted_v
      except WrongParameterTypeError: raise
      except Exception as e:
          current_app.logger.error(f"Could not convert parameter '{k}' with value '{v}' using {convertf.__name__}: {e} - {traceback.format_exc()}")
          raise WrongParameterTypeError(v, str(convertf), k)
    else:
        current_app.logger.debug(f"Ignoring unknown query parameter: {k}")
  return get_videos(url, extra_params)

@route_api('info')
@set_access_control
def info():
  try: result_data = get_result()
  except Exception as e:
    if isinstance(e, (yt_dlp.utils.DownloadError, yt_dlp.utils.ExtractorError, WrongParameterTypeError)): raise
    current_app.logger.error(f"Unexpected error in /info route during get_result: {e}\n{traceback.format_exc()}")
    return jsonify({'error': f"An unexpected error occurred processing your request."}), 500

  if result_data is None:
      current_app.logger.error(f"get_result() returned None for URL: {request.args.get('url')}. Cannot build response.")
      # This case might be covered by yt-dlp errors already, but as a safeguard:
      return jsonify({'error': 'Failed to retrieve video information. The video might be private, unavailable, or the URL is incorrect.'}), 500

  url = request.args['url']
  key = 'info'
  if query_bool(request.args.get('flatten'), 'flatten', False):
    final_data = flatten_result(result_data)
    key = 'videos'
  else: final_data = result_data
  return jsonify({'url': url, key: final_data})

@route_api('play')
@set_access_control
def play():
  try: result_data = get_result()
  except Exception as e:
    if isinstance(e, (yt_dlp.utils.DownloadError, yt_dlp.utils.ExtractorError, WrongParameterTypeError)): raise
    current_app.logger.error(f"Unexpected error in /play route during get_result: {e}\n{traceback.format_exc()}")
    return jsonify({'error': f"An unexpected error occurred processing your request."}), 500

  if result_data is None:
      current_app.logger.error("get_result() returned None for /play endpoint. Cannot redirect.")
      return jsonify({'error': 'Failed to retrieve video information for play. The video might be private, unavailable, or the URL is incorrect.'}), 500

  flat_results = flatten_result(result_data)
  if not flat_results or not isinstance(flat_results, list) or not flat_results[0] or 'url' not in flat_results[0]:
      current_app.logger.error(f"Could not extract a playable URL. Flattened result: {flat_results}")
      return jsonify({'error': 'Could not extract a playable URL from the video information.'}), 404
  return redirect(flat_results[0]['url'])

@route_api('extractors')
@set_access_control
def list_extractors():
  return jsonify(extractors=[{'name': ie.IE_NAME, 'working': ie.working()}
                             for ie in yt_dlp.extractor.gen_extractors()])

@route_api('version')
@set_access_control
def version():
  return jsonify({'yt-dlp': yt_dlp_version, 'yt-dlp-api-server': "0.3"}) # Version as string


app = Flask(__name__)

# Configure Flask's built-in logger
LOG_FORMAT_FLASK = '%(asctime)s [%(levelname)s] %(name)s (Flask App): %(message)s'
app.logger.setLevel(logging.DEBUG) # Set to DEBUG to catch all levels
# Remove default handlers if any, to avoid duplicate logs if running with Gunicorn
if app.logger.hasHandlers():
    app.logger.handlers.clear()

stream_handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(LOG_FORMAT_FLASK)
stream_handler.setFormatter(formatter)
app.logger.addHandler(stream_handler)
app.logger.propagate = False # Prevent logs from propagating to the root logger if Gunicorn also configures it

app.logger.info("Flask app.logger explicitly configured with StreamHandler to stdout and DEBUG level.")


app.register_blueprint(api)

# --- Configuration Loading ---
# Try to load from instance folder first (good for sensitive data not in repo)
# For Railway, environment variables are preferred.
# config.py in instance folder example:
# YOUTUBE_COOKIES_CONTENT = "your cookie data here" (though better as env var)
# COOKIES_FILE_PATH = "/app/config/cookies.txt" (if you mount a volume or include in Docker image)

# Load default config from a file relative to the app, e.g., 'default_config.py'
# This file can be in your Git repo.
# app.config.from_pyfile('default_config.py', silent=True)

# Load instance-specific config (not in Git repo, e.g., instance/config.py)
# app.config.from_pyfile(os.path.join(app.instance_path, 'config.py'), silent=True)

# Load from environment variables (Railway uses this heavily)
# Example: export APP_SETTING_KEY="value"
# app.config.from_envvar('YOUR_APP_SETTINGS_ENV_VAR', silent=True) # if you have a single env var pointing to a config file
# Or directly:
# app.config['FORBIDDEN_USER_AGENTS'] = os.environ.get('FORBIDDEN_USER_AGENTS', '').split(',')

# Your original config loading:
cfg_file_path_original = '../application.cfg' # This path is relative to app.py's location
                                            # If app.py is in root, it looks for application.cfg outside the project.
                                            # If app.py is in a subdir like 'src', it looks in the project root.
                                            # For Railway, this is likely not found unless you structure it that way.
app.config.from_pyfile(cfg_file_path_original, silent=True)
if os.path.exists(cfg_file_path_original) and app.config.get('SECRET_KEY'): # Check if some key was loaded
    app.logger.info(f"Config file '{cfg_file_path_original}' loaded.")
elif os.path.exists(cfg_file_path_original):
    app.logger.info(f"Config file '{cfg_file_path_original}' found but might be empty or missing expected keys.")
else:
    app.logger.info(f"Config file '{cfg_file_path_original}' not found. Using defaults/env vars.")


@app.route('/api', methods=['GET']) # Changed from '/' to '/api' to match your blueprint intent
def index_api_base(): # Renamed to avoid conflict with potential root index
    return "yt-dlp API server is running. See /api/info, /api/play, /api/extractors, /api/version."

# The /directory/ and /download/ routes seem intended for local file serving.
# On Railway's ephemeral filesystem, this might not be very useful unless you're downloading
# to a persistent volume (if Railway offers that easily) or just for temporary inspection.
# For now, I'll keep them but note their limitations in such an environment.

home_directory = os.path.expanduser("~") # On Railway, this will be some ephemeral user's home
# 'shared_space' calculation could be problematic on Railway if instance_path isn't what you expect.
# It's generally safer to define an explicit path, perhaps via an environment variable,
# or use a known temporary directory.
# For Railway, if you need persistent storage, look into their volume/disk options.
# If it's just for temporary files during a request, tempfile module is better.
# Let's assume 'shared_space' is meant to be a specific writable directory in your app deployment.
# A common practice is to create a 'downloads' or 'tmp' folder in your project and refer to it.
# For Railway, '/tmp' is usually writable but ephemeral.
_project_root = os.path.dirname(os.path.abspath(__file__))
shared_space = os.path.join(_project_root, 'app_data') # Example: creating an 'app_data' dir in your project
try:
    os.makedirs(shared_space, exist_ok=True)
    app.logger.info(f"Shared space for directory view: {shared_space}")
except OSError as e:
    app.logger.error(f"Could not create shared_space directory {shared_space}: {e}")
    # shared_space = tempfile.gettempdir() # Fallback to system temp if creation fails
    # app.logger.warning(f"Falling back to system temp for shared_space: {shared_space}")


@app.route('/')
def root_index():
    # Simple HTML page with links to API endpoints or documentation
    return render_template('index.html') # You'll need an templates/index.html

@app.route('/directory/')
@app.route('/directory/<path:folder>/')
def directory(folder=''):
    logger = current_app.logger
    abs_shared_space_check = os.path.abspath(shared_space)
    if not os.path.isdir(abs_shared_space_check):
        logger.error(f"Shared space directory '{shared_space}' (resolved to {abs_shared_space_check}) not found or not a directory.")
        abort(500, "Server file storage is not correctly configured.")

    # Normalize folder path to prevent '..' traversal issues before joining
    norm_folder = os.path.normpath(folder)
    if norm_folder.startswith('..') or norm_folder.startswith('/'): # Basic security check
        logger.warning(f"Invalid folder path detected: {folder}")
        abort(400, "Invalid folder path.")

    folder_path = os.path.join(shared_space, norm_folder)
    abs_folder_path = os.path.abspath(folder_path)

    if not abs_folder_path.startswith(abs_shared_space_check) or not os.path.isdir(abs_folder_path):
        logger.warning(f"Directory access denied/not found: {folder_path} (resolved: {abs_folder_path}, base: {abs_shared_space_check})")
        abort(404)
    try:
        files = get_file_list(abs_folder_path)
        # Add parent directory link if not at the root of shared_space
        parent_folder_link = None
        if abs_folder_path != abs_shared_space_check:
            parent_folder_rel = os.path.dirname(norm_folder)
            if parent_folder_rel == '.': parent_folder_rel = ''
            parent_folder_link = url_for('directory', folder=parent_folder_rel)

    except OSError as e:
        logger.error(f"Error listing directory {abs_folder_path}: {e}")
        abort(500)
    return render_template('directory.html', files=files, current_folder_display=folder if folder else "Root", parent_folder_link=parent_folder_link, base_folder_segment=folder)


@app.route('/download/<path:filepath>') # Simplified route
def download_file_simplified(filepath):
    logger = current_app.logger
    abs_shared_space_check = os.path.abspath(shared_space)

    # Normalize filepath to prevent '..' traversal issues
    norm_filepath = os.path.normpath(filepath)
    if norm_filepath.startswith('..') or norm_filepath.startswith('/'):
        logger.warning(f"Invalid file path detected for download: {filepath}")
        abort(400, "Invalid file path.")

    abs_file_path = os.path.abspath(os.path.join(shared_space, norm_filepath))

    if not abs_file_path.startswith(abs_shared_space_check):
        logger.warning(f"File download attempt outside shared space: {abs_file_path} (base: {abs_shared_space_check})")
        abort(403) # Forbidden

    if not os.path.isfile(abs_file_path):
        logger.warning(f"File download denied/not found: {norm_filepath} (resolved: {abs_file_path})")
        abort(404)

    # send_from_directory requires the directory and the filename separately
    directory_path = os.path.dirname(abs_file_path)
    filename = os.path.basename(abs_file_path)
    return send_from_directory(directory_path, filename, as_attachment=True)


def get_file_list(folder_path_abs):
    logger = current_app.logger
    items = []
    if not os.path.isdir(folder_path_abs):
        logger.error(f"get_file_list called with non-directory: {folder_path_abs}")
        raise OSError(f"Not a directory: {folder_path_abs}")
    for item_name in os.listdir(folder_path_abs):
        item_path_abs = os.path.join(folder_path_abs, item_name)
        # Construct relative path from shared_space for URL generation
        item_path_rel = os.path.relpath(item_path_abs, shared_space)
        if os.path.isfile(item_path_abs):
            items.append({'name': item_name, 'type': 'file', 'path': item_path_rel})
        elif os.path.isdir(item_path_abs):
            items.append({'name': item_name, 'type': 'folder', 'path': item_path_rel})
    return items

if __name__ == '__main__':
  # This block runs only when script is executed directly (e.g. `python app.py`)
  # Gunicorn or other WSGI servers will import the 'app' object and have their own logging.
  LOG_FORMAT_MAIN = '%(asctime)s [%(levelname)s] %(name)s (Direct Run): %(message)s'
  logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=LOG_FORMAT_MAIN) # Basic config for other modules

  # Flask app logger was already configured above, ensure its level is also DEBUG for direct run
  app.logger.setLevel(logging.DEBUG)
  app.logger.info("Flask app logger re-confirmed to DEBUG for direct run.")

  # app.config["CACHE_TYPE"] = "null" # Not standard Flask, usually for Flask-Caching extension
  port = int(os.environ.get('PORT', 5000))
  host = '0.0.0.0'
  app.logger.info(f"Starting WSGIServer (gevent) on {host}:{port}")
  http_server = WSGIServer((host, port), app, log=app.logger, error_log=app.logger)
  try:
      http_server.serve_forever()
  except KeyboardInterrupt:
      app.logger.info("Server shutting down due to KeyboardInterrupt.")
