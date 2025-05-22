import functools
import logging
import traceback # Added for better error logging
import sys
import os # Already present, but ensure it's used for os.environ, os.path etc.
import tempfile # Added for temporary cookie file handling

from flask import Flask, Blueprint, current_app, jsonify, request, redirect, abort
from io import BytesIO # Not directly used in the provided snippet, but keeping if used elsewhere
from flask import render_template, send_from_directory, url_for, send_file # Grouped Flask imports
from pathlib import Path # Not directly used in the provided snippet, but keeping if used elsewhere
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

# --- MODIFIED get_videos function ---
def get_videos(url, extra_params):
    '''
    Get a list with a dict for every video founded
    '''
    ydl_params = {
        'format': 'best',  # Or your preferred format
        'cachedir': False,
        'verbose': current_app.config.get('YTDLP_VERBOSE', os.environ.get('YTDLP_VERBOSE', 'false').lower() == 'true'),
        'logger': current_app.logger.getChild('yt-dlp'),
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    }

    temp_cookie_file_path = None
    
    cookie_content_env = os.environ.get('YOUTUBE_COOKIES_CONTENT')
    if cookie_content_env:
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8') as tmpfile:
                tmpfile.write(cookie_content_env)
                temp_cookie_file_path = tmpfile.name
            ydl_params['cookies'] = temp_cookie_file_path
            current_app.logger.info(f"Using cookies from temporary file (via env var YOUTUBE_COOKIES_CONTENT): {temp_cookie_file_path}")
        except Exception as e:
            current_app.logger.error(f"Error creating temporary cookie file from env var: {e} - {traceback.format_exc()}")
            if temp_cookie_file_path and os.path.exists(temp_cookie_file_path):
                try: os.remove(temp_cookie_file_path)
                except OSError: pass
            temp_cookie_file_path = None
    
    if 'cookies' not in ydl_params:
        # Check for YTDLP_COOKIES_FILE from application.cfg
        # Make sure your application.cfg defines YTDLP_COOKIES_FILE = 'cookies.txt' (or similar)
        # And that cookies.txt is in the correct relative path to where application.cfg is loaded from.
        # Your app.config.from_pyfile('../application.cfg', silent=True) means application.cfg is one level up.
        # So 'cookies.txt' would be expected in that same directory (one level up from app.py).
        
        configured_cookie_file = current_app.config.get('YTDLP_COOKIES_FILE')
        if configured_cookie_file:
            # Construct path relative to where app.py is, assuming application.cfg is one level up
            # and cookies.txt is next to application.cfg.
            # Path to the directory containing app.py
            current_script_dir = os.path.dirname(os.path.abspath(__file__))
            # Path to the directory containing application.cfg (one level up)
            project_root_dir = os.path.abspath(os.path.join(current_script_dir, '..'))
            # Path to the cookie file relative to the project root
            actual_cookie_file_path = os.path.join(project_root_dir, configured_cookie_file)

            if os.path.exists(actual_cookie_file_path):
                ydl_params['cookies'] = actual_cookie_file_path
                current_app.logger.info(f"Using cookies from configured file (YTDLP_COOKIES_FILE): {actual_cookie_file_path}")
            else:
                current_app.logger.warning(
                    f"Cookie file specified in config (YTDLP_COOKIES_FILE='{configured_cookie_file}') not found. "
                    f"Checked at: {actual_cookie_file_path}"
                )
        else:
            current_app.logger.info("No YOUTUBE_COOKIES_CONTENT env var and no YTDLP_COOKIES_FILE in app config. Proceeding without cookies (likely to cause YouTube 'bot' errors).")
    
    ydl_params.update(extra_params)
    
    # For debugging, you might want to see the final options being passed to yt-dlp
    # current_app.logger.debug(f"Final ydl_params for URL '{url}': { {k:v for k,v in ydl_params.items() if k != 'cookies'} }")
    # if 'cookies' in ydl_params:
    #    current_app.logger.debug(f"Cookies are being used from: {ydl_params['cookies']}")

    ydl = SimpleYDL(ydl_params)
    
    res = None # Initialize res
    try:
        res = ydl.extract_info(url, download=False)
    finally:
        if temp_cookie_file_path and os.path.exists(temp_cookie_file_path):
            try:
                os.remove(temp_cookie_file_path)
                current_app.logger.info(f"Removed temporary cookie file: {temp_cookie_file_path}")
            except OSError as e_remove:
                current_app.logger.error(f"Error removing temporary cookie file {temp_cookie_file_path}: {e_remove}")
    
    return res
# --- END OF MODIFIED get_videos function ---

def flatten_result(result):
  # Safety check if result is None (e.g., if extract_info failed before returning)
  if result is None:
    return [] # Or handle as an error appropriately
  r_type = result.get('_type', 'video')
  if r_type == 'video':
    videos = [result]
  elif r_type == 'playlist':
    videos = []
    if 'entries' in result and result['entries'] is not None: # Check for None entries
        for entry in result['entries']:
            if entry: # Check if entry itself is not None
                videos.extend(flatten_result(entry))
    else:
        current_app.logger.warning(f"Playlist result for {result.get('webpage_url', 'unknown URL')} has no 'entries' or entries is None.")
  elif r_type == 'compat_list':
    videos = []
    if 'entries' in result and result['entries'] is not None: # Check for None entries
        for r_entry in result['entries']:
            if r_entry: # Check if r_entry itself is not None
                videos.extend(flatten_result(r_entry))
    else:
        current_app.logger.warning(f"Compat_list result for {result.get('webpage_url', 'unknown URL')} has no 'entries' or entries is None.")
  else: # Handle cases where r_type is not recognized or result is malformed
    current_app.logger.warning(f"Unrecognized result type '{r_type}' or malformed result for URL (if available): {result.get('webpage_url', 'N/A')}. Result content: {str(result)[:200]}")
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
  current_app.logger.error(f"yt-dlp Error: {str(error)} - {traceback.format_exc()}")
  result = jsonify({'error': str(error)})
  result.status_code = 500
  return result

class WrongParameterTypeError(ValueError):
  def __init__(self, value, type, parameter):
    message = '"{}" expects a {}, got "{}"'.format(parameter, type, value)
    super(WrongParameterTypeError, self).__init__(message)

@api.errorhandler(WrongParameterTypeError)
def handle_wrong_parameter(error):
  current_app.logger.error(f"Wrong Parameter: {str(error)} - {traceback.format_exc()}")
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
    # It's good practice to also allow yt-dlp's own options if needed,
    # but be careful not to expose sensitive ones like 'cookies' directly via URL params.
    # 'username': str, # Example, but handle credentials with extreme care
    # 'password': str, # Example, but handle credentials with extreme care
}

def get_result():
  if 'url' not in request.args:
      current_app.logger.error("API request made without 'url' parameter.")
      abort(400, description="Missing 'url' parameter.") # Abort with a 400 Bad Request

  url = request.args['url']
  extra_params = {}
  for k, v in request.args.items():
    if k == 'url': # Skip 'url' itself, it's handled separately
        continue
    if k in ALLOWED_EXTRA_PARAMS:
      convertf = ALLOWED_EXTRA_PARAMS[k]
      try:
        if convertf == bool:
            converted_v = query_bool(v, k)
        elif convertf == list:
            converted_v = v.split(',')
        else:
            converted_v = convertf(v)
        extra_params[k] = converted_v
      except WrongParameterTypeError: # Catch error from query_bool
          raise # Re-raise to be caught by the error handler
      except Exception as e:
          current_app.logger.warning(f"Could not convert parameter '{k}' with value '{v}' using {convertf}: {e}")
          # Depending on strictness, you might want to raise an error here or just skip the param
          # For now, let's be strict and raise a custom error or re-raise.
          raise WrongParameterTypeError(v, convertf.__name__, k)
    else:
        current_app.logger.debug(f"Ignoring unknown query parameter: {k}")

  return get_videos(url, extra_params)

@route_api('info')
@set_access_control
def info():
  # get_result can now abort, so ensure it's called and result is checked
  try:
    result_data = get_result()
  except Exception as e: # Catch potential errors from get_result itself if not handled by errorhandlers
    current_app.logger.error(f"Error in get_result for /info: {e} - {traceback.format_exc()}")
    return jsonify({'error': f"Failed to process request: {str(e)}"}), 500
  
  if result_data is None: # If get_videos returns None due to an issue not raising an exception
      current_app.logger.error("get_result() returned None for /info endpoint.")
      return jsonify({'error': "Failed to extract video information."}), 500

  url = request.args['url'] # Already checked in get_result but good for response structure
  key = 'info'
  
  # Use a default for 'flatten' if not provided
  should_flatten = query_bool(request.args.get('flatten'), 'flatten', default=False)
  if should_flatten:
    final_data = flatten_result(result_data)
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
  # get_result can now abort
  try:
    result_data = get_result()
  except Exception as e:
    current_app.logger.error(f"Error in get_result for /play: {e} - {traceback.format_exc()}")
    return jsonify({'error': f"Failed to process request for play: {str(e)}"}), 500
  
  if result_data is None:
      current_app.logger.error("get_result() returned None for /play endpoint.")
      return jsonify({'error': "Failed to extract video information for play."}), 500

  flat_results = flatten_result(result_data)
  if not flat_results or 'url' not in flat_results[0]:
    current_app.logger.error(f"Could not find a playable URL after flattening. Original result: {str(result_data)[:500]}")
    return jsonify({'error': 'Could not extract a playable URL from the video information.'}), 404
  
  return redirect(flat_results[0]['url'])

@route_api('extractors')
@set_access_control
def list_extractors():
  ie_list = [{
      'name': ie.IE_NAME,
      # 'description': ie.IE_DESC, # Could be useful
      'working': ie.working(),
  } for ie in yt_dlp.extractor.gen_extractors()] # Corrected to use yt_dlp.extractor
  return jsonify(extractors=ie_list)

@route_api('version')
@set_access_control
def version():
  result = {
      'yt-dlp': yt_dlp_version,
      'yt-dlp-api-server': "0.3-modified", # Indicate it's based on 0.3 but with changes
  }
  return jsonify(result)

app = Flask(__name__)

# --- Configuration Loading ---
# Determine the path to application.cfg relative to this app.py file.
# If app.py is at the root, it's 'application.cfg'.
# If app.py is in a subdirectory like 'src/', and application.cfg is at the root,
# then '../application.cfg' is correct.
# The code `os.path.join(os.path.dirname(app.instance_path), os.sep, '')` for shared_space
# also suggests app.py might be in a subdirectory. Let's assume '../application.cfg' is intended.
cfg_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'application.cfg')
if os.path.exists(cfg_file_path):
    app.config.from_pyfile(cfg_file_path, silent=False) # Make it non-silent to see errors if cfg fails to load
    app.logger.info(f"Loaded configuration from: {cfg_file_path}")
else:
    app.logger.warning(f"Application configuration file not found at: {cfg_file_path}. Using defaults.")
# Fallback or default configurations can be set here if application.cfg is not found or doesn't set them
app.config.setdefault('YTDLP_VERBOSE', False)
app.config.setdefault('FORBIDDEN_USER_AGENTS', [])
# --- End Configuration Loading ---

app.register_blueprint(api)


@app.route('/api', methods=['GET']) # This is a bit redundant if the blueprint handles /api/*
def api_base_index():
  return "yt-dlp API server is running. Use specific endpoints like /api/info or /api/version."

# --- Directory Browsing and File Serving ---
# The logic for 'shared_space' needs to be robust.
# os.path.dirname(app.instance_path) usually points to an 'instance' folder next to your app package,
# or inside it, depending on how Flask is structured.
# If you want a 'downloads' folder at the project root (where application.cfg might be):
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
# If app.py is at the root itself, then project_root = os.path.dirname(__file__)
# Let's assume app.py is in a subdir and you want 'downloads' at the parent (project root)
default_shared_space = os.path.join(project_root, 'downloads') # Example: /project_root/downloads/
shared_space = app.config.get('SHARED_DOWNLOAD_PATH', default_shared_space)

# Ensure the shared_space directory exists, create if not (optional)
if not os.path.exists(shared_space):
    try:
        os.makedirs(shared_space)
        app.logger.info(f"Created shared download directory: {shared_space}")
    except OSError as e:
        app.logger.error(f"Could not create shared download directory {shared_space}: {e}")
        # Potentially abort or use a fallback if this directory is critical.

@app.route('/')
def home_index():
    # Could serve a simple HTML page or redirect to /api documentation
    return "Welcome to the yt-dlp server. API is at /api/info etc. File browser (if enabled) at /directory/"

@app.route('/directory/')
@app.route('/directory/<path:folder>/')
def directory(folder=''):
    # Sanitize folder input to prevent directory traversal outside shared_space
    # os.path.join will handle path separators correctly.
    # os.path.abspath will resolve '..' but we need to ensure it's still within shared_space.
    requested_path = os.path.abspath(os.path.join(shared_space, folder))

    # Security: Check if the requested_path is still within or same as shared_space
    if not requested_path.startswith(os.path.abspath(shared_space)):
        app.logger.warning(f"Directory traversal attempt blocked: {folder} resolved to {requested_path} which is outside {shared_space}")
        abort(404) # Or 403 Forbidden

    if not os.path.isdir(requested_path):
        app.logger.warning(f"Directory not found: {requested_path}")
        abort(404)

    try:
        files = get_file_list(requested_path)
        # Make 'folder' relative to shared_space for display and navigation
        relative_folder = os.path.relpath(requested_path, shared_space)
        if relative_folder == '.': # Root of shared_space
            relative_folder = ''
        
        # Parent directory logic
        parent_folder = None
        if relative_folder: # Not at the root of shared_space
            parent_folder = os.path.dirname(relative_folder)
            if parent_folder == '.': # Parent is root
                 parent_folder = '' # Link to /directory/

        return render_template('directory.html', 
                               files=files, 
                               current_folder_name=os.path.basename(requested_path) if relative_folder else os.path.basename(shared_space),
                               current_folder_path_relative=relative_folder,
                               parent_folder_path_relative=parent_folder)
    except OSError as e:
        app.logger.error(f"Error listing directory {requested_path}: {e}")
        abort(500, description="Error accessing directory contents.")


@app.route('/download_file/<path:filepath_relative>') # Changed route to be more explicit
def download_file_route(filepath_relative): # Renamed function and param
    # filepath_relative is path relative to shared_space
    full_file_path = os.path.abspath(os.path.join(shared_space, filepath_relative))

    # Security: Check if the full_file_path is within shared_space and is a file
    if not full_file_path.startswith(os.path.abspath(shared_space)) or not os.path.isfile(full_file_path):
        app.logger.warning(f"File download attempt blocked or file not found: {filepath_relative} resolved to {full_file_path}")
        abort(404)
    
    # send_from_directory expects directory and filename separately
    directory_part = os.path.dirname(full_file_path)
    filename_part = os.path.basename(full_file_path)
    
    try:
        return send_from_directory(directory_part, filename_part, as_attachment=True)
    except Exception as e:
        app.logger.error(f"Error sending file {full_file_path}: {e}")
        abort(500)

def get_file_list(folder_path_abs):
    items = []
    try:
        for item_name in os.listdir(folder_path_abs):
            item_abs_path = os.path.join(folder_path_abs, item_name)
            item_rel_path = os.path.relpath(item_abs_path, shared_space) # Path relative to shared_space
            
            if os.path.isfile(item_abs_path):
                items.append({'name': item_name, 'type': 'file', 'path': item_rel_path})
            elif os.path.isdir(item_abs_path):
                items.append({'name': item_name, 'type': 'folder', 'path': item_rel_path})
    except OSError as e:
        app.logger.error(f"Cannot list directory {folder_path_abs}: {e}")
        # Raise or return empty list depending on desired behavior
        raise # Re-raise to be caught by the caller (directory view)
    return items
# --- End Directory Browsing ---

if __name__ == '__main__':
  # Configure basic logging
  logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
  
  # Set Flask's logger level from app config or default to INFO
  # This needs to happen AFTER app is created and config loaded.
  flask_log_level_str = app.config.get('LOG_LEVEL', 'INFO').upper()
  flask_log_level = getattr(logging, flask_log_level_str, logging.INFO)
  app.logger.setLevel(flask_log_level)
  # Also set for werkzeug if you want to see its logs (can be noisy)
  # logging.getLogger('werkzeug').setLevel(flask_log_level)


  app.config["CACHE_TYPE"] = "null" # Usually for development
  
  # Determine port and host
  port = int(os.environ.get('PORT', 5000)) # Railway typically sets PORT env var
  host = '0.0.0.0' # Listen on all available interfaces

  app.logger.info(f"Starting WSGIServer on {host}:{port}")
  http_server = WSGIServer((host, port), app)
  try:
    http_server.serve_forever()
  except KeyboardInterrupt:
    app.logger.info("Server shutting down.")
