import functools
import logging
import traceback
import sys
from flask import Flask, Blueprint, current_app, jsonify, request, redirect, abort
from io import BytesIO
from flask import render_template, send_from_directory, url_for, send_file
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
            
            # --- CRITICAL CORRECTION: Use 'cookies' option, not 'cookiesfrombrowser' ---
            ydl_params['cookies'] = temp_cookie_file_path 
            current_app.logger.info(f"Using 'cookies' option with temporary cookie file: {temp_cookie_file_path}")
            # --- END CRITICAL CORRECTION ---
            
        except Exception as e:
            current_app.logger.error(f"Failed to create or use temporary cookie file: {e} - {traceback.format_exc()}")
            if temp_cookie_file_path and os.path.exists(temp_cookie_file_path):
                try: os.remove(temp_cookie_file_path)
                except OSError: pass 
            temp_cookie_file_path = None # Ensure it's None if creation failed
    
    # Fallback to a configured cookie file path if the environment variable method wasn't used or failed
    if 'cookies' not in ydl_params:
        # Example of how you might configure a fallback path via app.config or another env var
        # In your Railway env vars or a config file: COOKIES_FILE_PATH = 'path/to/your/cookies.txt'
        configured_cookie_file = current_app.config.get('COOKIES_FILE_PATH') or os.environ.get('COOKIES_FILE_PATH')
        if configured_cookie_file:
            if os.path.exists(configured_cookie_file):
                ydl_params['cookies'] = configured_cookie_file
                current_app.logger.info(f"Using 'cookies' (fallback) from configured COOKIES_FILE_PATH: {configured_cookie_file}")
            else:
                current_app.logger.warning(f"Cookies file specified in COOKIES_FILE_PATH ('{configured_cookie_file}') not found.")
        else:
             current_app.logger.info("No YOUTUBE_COOKIES_CONTENT env var and no COOKIES_FILE_PATH configured. Proceeding without explicit cookies.")
  
    if 'cookies' not in ydl_params :
        current_app.logger.warning("No cookies configured for yt-dlp for this request.")
  
    current_app.logger.info(f"yt-dlp verbose initial state: {ydl_params.get('verbose')}")
    ydl_params.update(extra_params) 
    current_app.logger.info(f"Final yt-dlp verbose state after extra_params.update: {ydl_params.get('verbose')}")
    
    loggable_params = {k: v for k, v in ydl_params.items()}
    if 'cookies' in loggable_params and loggable_params['cookies']:
      loggable_params['cookies'] = f"[path_to_cookie_file: {loggable_params['cookies']}]" 
    current_app.logger.debug(f"Final ydl_params for yt-dlp: {loggable_params}")

    ydl = SimpleYDL(ydl_params)
    res = None 
    try:
        res = ydl.extract_info(url, download=False)
    except Exception as e:
        # Log the specific yt-dlp error here before re-raising
        # This helps see the root cause even if Flask's handler formats it differently
        current_app.logger.error(f"Error during yt-dlp extract_info for URL '{url}': {type(e).__name__} - {str(e)}")
        current_app.logger.debug(traceback.format_exc()) # Full traceback for debug level
        raise # Re-raise the exception so it can be handled by Flask error handlers
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
  current_app.logger.error(f"yt-dlp Download/Extractor Error: {str(error)}")
  # Full traceback is already logged in get_videos or will be by default Flask error handler for unhandled ones
  # Avoid logging full traceback here if already logged, to prevent duplication.
  # Instead, focus on a user-friendly message.
  
  public_error_message = "A download or extraction error occurred with the video provider."
  # Try to make the error message a bit more specific if it's a common, safe one
  err_str = str(error).lower()
  if "private video" in err_str:
      public_error_message = "This video is private. Cookies may be required."
  elif "video unavailable" in err_str:
      public_error_message = "This video is unavailable."
  elif "is not a valid url" in err_str or "unsupported url" in err_str:
      public_error_message = "The provided URL is invalid or unsupported."
  elif "login required" in err_str:
      public_error_message = "Login is required to access this video. Please ensure your cookies are valid."
  elif "cookie" in err_str and "firefox" not in err_str : # Generic cookie error but not the firefox db error
      public_error_message = "A cookie-related error occurred. The cookies might be invalid or expired."
  # If the error message from yt-dlp starts with "ERROR:", use the part after it.
  elif str(error).startswith('ERROR:'):
      public_error_message = str(error).split('ERROR:', 1)[-1].strip()


  result = jsonify({'error': public_error_message})
  result.status_code = 500 # Could also be 400 for bad URL, 403 for private, 404 for unavailable
                           # but 500 is a safe default if yt-dlp couldn't process.
  return result

class WrongParameterTypeError(ValueError):
  def __init__(self, value, type, parameter):
    message = '"{}" expects a {}, got "{}"'.format(parameter, type, value)
    super(WrongParameterTypeError, self).__init__(message)

@api.errorhandler(WrongParameterTypeError)
def handle_wrong_parameter(error):
  current_app.logger.warning(f"Wrong Parameter Type Error: {str(error)}") # Log as warning, it's client error
  # No need for full traceback for client errors unless debugging client behavior
  result = jsonify({'error': str(error)})
  result.status_code = 400
  return result

@api.before_request
def block_on_user_agent():
  # This runs for all requests to the app, including those not part of the blueprint
  # If you want it only for API requests, move it to @api.before_request
  if request.blueprint == 'api': # Apply only to API blueprint
    user_agent = request.user_agent.string
    forbidden_uas_str = current_app.config.get('FORBIDDEN_USER_AGENTS', os.environ.get('FORBIDDEN_USER_AGENTS', ''))
    forbidden_uas = [ua.strip() for ua in forbidden_uas_str.split(',') if ua.strip()]
    if user_agent in forbidden_uas: 
        current_app.logger.warning(f"Forbidden User-Agent blocked: {user_agent}")
        abort(429) # Too Many Requests (or 403 Forbidden)

def query_bool(value, name, default=None):
  if value is None: return default
  if isinstance(value, bool): return value # Already a bool
  value = str(value).lower()
  if value == 'true': return True
  elif value == 'false': return False
  else: raise WrongParameterTypeError(value, 'bool', name)

ALLOWED_EXTRA_PARAMS = {
    'format': str, 'playliststart': int, 'playlistend': int, 'playlist_items': str,
    'playlistreverse': bool, 'matchtitle': str, 'rejecttitle': str, 'writesubtitles': bool,
    'writeautomaticsub': bool, 'allsubtitles': bool, 'subtitlesformat': str, 'subtitleslangs': list,
    'verbose': bool # Allow 'verbose' to be passed as an API param to override server default
}

def get_result():
  if 'url' not in request.args:
      current_app.logger.warning("API request made without 'url' parameter.")
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
          current_app.logger.error(f"Could not convert parameter '{k}' with value '{v}' to {convertf.__name__}: {e}")
          # Log traceback for unexpected conversion errors
          current_app.logger.debug(traceback.format_exc())
          raise WrongParameterTypeError(v, convertf.__name__, k)
    else:
        # Log unknown parameters only if verbose/debug logging is on for the app
        if current_app.logger.isEnabledFor(logging.DEBUG):
            current_app.logger.debug(f"Ignoring unknown query parameter: {k}")
  return get_videos(url, extra_params)

@route_api('info')
@set_access_control
def info():
  try: result_data = get_result()
  except Exception as e: 
    # Errors like DownloadError, ExtractorError, WrongParameterTypeError are already handled
    # by their specific error handlers if they are raised from get_result.
    # This catch is for other unexpected errors within this route's logic,
    # or if an error handler re-raises an exception.
    if not isinstance(e, (yt_dlp.utils.DownloadError, yt_dlp.utils.ExtractorError, WrongParameterTypeError)):
        current_app.logger.error(f"Unexpected error in /info route: {type(e).__name__} - {e}")
        current_app.logger.debug(traceback.format_exc())
        return jsonify({'error': f"An unexpected server error occurred."}), 500
    raise # Re-raise to let dedicated handlers manage it

  if result_data is None: # Should be caught by yt-dlp errors, but as a safeguard
      current_app.logger.error(f"get_result() returned None for URL: {request.args.get('url')} (this should ideally be an exception from yt-dlp).")
      return jsonify({'error': 'Failed to retrieve video information; the resource might be unavailable or the URL incorrect.'}), 500

  url = request.args['url'] # Already validated by get_result
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
    if not isinstance(e, (yt_dlp.utils.DownloadError, yt_dlp.utils.ExtractorError, WrongParameterTypeError)):
        current_app.logger.error(f"Unexpected error in /play route: {type(e).__name__} - {e}")
        current_app.logger.debug(traceback.format_exc())
        return jsonify({'error': f"An unexpected server error occurred."}), 500
    raise

  if result_data is None:
      current_app.logger.error("get_result() returned None for /play endpoint (should be an exception).")
      return jsonify({'error': 'Failed to retrieve video information for play; resource unavailable or URL incorrect.'}), 500
  
  flat_results = flatten_result(result_data) 
  if not flat_results or not isinstance(flat_results, list) or not flat_results[0] or 'url' not in flat_results[0]:
      current_app.logger.warning(f"Could not extract a playable URL. Flattened result for {request.args.get('url')}: {flat_results[:1]}") # Log only first item for brevity
      return jsonify({'error': 'Could not extract a playable URL from the video information. The format might not be available directly.'}), 404
  return redirect(flat_results[0]['url'])

@route_api('extractors')
@set_access_control
def list_extractors():
  return jsonify(extractors=[{'name': ie.IE_NAME, 'working': ie.working()} 
                             for ie in yt_dlp.extractor.gen_extractors()])

@route_api('version')
@set_access_control
def version():
  return jsonify({'yt-dlp': yt_dlp_version, 'yt-dlp-api-server': "0.3"})


app = Flask(__name__, instance_relative_config=True) # instance_relative_config=True is good practice

# --- Centralized Logger Configuration ---
def configure_logging(flask_app):
    log_level_str = os.environ.get('LOG_LEVEL', 'INFO').upper()
    log_level = getattr(logging, log_level_str, logging.INFO)

    # Configure Flask's built-in logger
    flask_log_format = '%(asctime)s [%(levelname)s] %(name)s (Flask App): %(message)s'
    
    # Remove default handlers added by Flask if any, to avoid duplicate logs
    # especially when Gunicorn or another WSGI server also configures logging.
    if flask_app.logger.hasHandlers():
        flask_app.logger.handlers.clear()

    stream_handler = logging.StreamHandler(sys.stdout) # Log to stdout for Railway
    formatter = logging.Formatter(flask_log_format)
    stream_handler.setFormatter(formatter)
    
    flask_app.logger.addHandler(stream_handler)
    flask_app.logger.setLevel(log_level)
    flask_app.logger.propagate = False # Prevent logs from propagating to the root logger

    # Configure root logger (for libraries like yt-dlp if they use logging.getLogger())
    # If you want library logs to also go through Flask's handlers, you can skip this
    # or ensure they don't also log to stdout directly.
    # For yt-dlp, we pass its logger instance, so its logs will use the 'app.yt-dlp' name.
    # We can configure 'app.yt-dlp' specifically if needed, or let it inherit from 'app'.
    yt_dlp_logger = logging.getLogger('app.yt-dlp') # Matches getChild('yt-dlp')
    if not yt_dlp_logger.handlers: # Add handler only if not already configured
        yt_dlp_logger.addHandler(stream_handler) # Can use the same handler
    yt_dlp_logger.setLevel(log_level) # Match app's log level, or set differently
    yt_dlp_logger.propagate = False # Don't propagate to root if handled here

    flask_app.logger.info(f"Flask app logger configured. Level: {log_level_str}")
    if log_level == logging.DEBUG:
        flask_app.logger.debug("Debug logging is enabled.")

configure_logging(app)
# --- End Logger Configuration ---


app.register_blueprint(api)

# --- Configuration Loading ---
# 1. Defaults (can be in code or a default_config.py)
app.config.from_mapping(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev_default_secret_key'), # Important for session, etc.
    # Add other defaults here
)

# 2. From a config.py file in the instance folder (good for secrets not in repo)
#    Instance folder is typically 'instance/' at the same level as your app package.
#    It needs to be created. Path: os.path.join(app.instance_path, 'config.py')
try:
    app.config.from_pyfile('config.py', silent=True) # e.g. instance/config.py
    if os.path.exists(os.path.join(app.instance_path, 'config.py')):
        app.logger.info(f"Loaded instance config from {os.path.join(app.instance_path, 'config.py')}")
except Exception as e:
    app.logger.warning(f"Could not load instance config: {e}")


# 3. From Environment Variables (Railway's preferred method)
#    You can prefix env vars, e.g., YOURAPP_SETTING_KEY
#    Or load specific ones:
app.config['FORBIDDEN_USER_AGENTS'] = os.environ.get('FORBIDDEN_USER_AGENTS', '') # Example

# Legacy config file path (application.cfg) - less ideal for Railway
cfg_file_path_original = '../application.cfg' # Relative to app.py's location
if os.path.exists(cfg_file_path_original):
    try:
        app.config.from_pyfile(cfg_file_path_original, silent=False) # Make it non-silent to see errors
        app.logger.info(f"Successfully loaded legacy config from '{cfg_file_path_original}'.")
    except Exception as e:
        app.logger.warning(f"Found legacy config '{cfg_file_path_original}' but failed to load: {e}")
else:
    app.logger.info(f"Legacy config file '{cfg_file_path_original}' not found. Using defaults/env vars.")


# --- Root and Static/File Browsing Routes ---

# Define where 'shared_space' for file browsing should be.
# For Railway, '/tmp' is writable but ephemeral.
# For persistent storage, you'd need Railway volumes.
# Let's default to a directory within the app, which is also ephemeral on redeploy
# but predictable.
_project_root = os.path.dirname(os.path.abspath(__file__))
# Using a directory named 'user_files' inside the project. Create it if it doesn't exist.
shared_space = os.path.join(_project_root, 'user_files')
try:
    os.makedirs(shared_space, exist_ok=True)
    app.logger.info(f"Shared space for directory view initialized at: {shared_space}")
except OSError as e:
    app.logger.error(f"Could not create shared_space directory {shared_space}: {e}. File browsing may fail.")
    # Fallback to system temp if creation fails, though less ideal for browsing
    # shared_space = tempfile.gettempdir() 
    # app.logger.warning(f"Falling back to system temp for shared_space: {shared_space}")


@app.route('/')
def root_index():
    # Serve a simple HTML page with links to API or documentation
    return render_template('index.html') # Requires templates/index.html

@app.route('/files/') # Changed route slightly to avoid conflict if 'directory' is a file/folder name
@app.route('/files/<path:folder>/')
def browse_directory(folder=''): # Renamed function
    logger = current_app.logger
    abs_shared_space_check = os.path.abspath(shared_space)

    if not os.path.isdir(abs_shared_space_check):
        logger.error(f"Shared space directory '{shared_space}' (resolved: {abs_shared_space_check}) not found.")
        abort(500, "Server file storage is not correctly configured.")

    # Normalize folder path carefully
    norm_folder = os.path.normpath(folder) 
    if norm_folder == '.': norm_folder = '' # Root of shared_space
    # Prevent escaping shared_space
    if norm_folder.startswith('/') or '..' in norm_folder.split(os.sep):
        logger.warning(f"Invalid or disallowed folder path traversal attempt: {folder}")
        abort(400, "Invalid folder path.")

    folder_path_to_browse = os.path.join(abs_shared_space_check, norm_folder)
    abs_folder_path_to_browse = os.path.abspath(folder_path_to_browse)

    # Final check to ensure we are within the shared_space
    if not abs_folder_path_to_browse.startswith(abs_shared_space_check) or not os.path.isdir(abs_folder_path_to_browse):
        logger.warning(f"Directory access denied or not found: {folder_path_to_browse} (relative: {norm_folder})")
        abort(404)
    
    try:
        files_and_dirs = get_file_list(abs_folder_path_to_browse) 
        parent_folder_link = None
        # Create parent link if not at the root of shared_space
        if abs_folder_path_to_browse != abs_shared_space_check:
            parent_rel_path = os.path.dirname(norm_folder)
            if parent_rel_path == '.': parent_rel_path = '' # Avoids '/files/./'
            parent_folder_link = url_for('browse_directory', folder=parent_rel_path)
            
    except OSError as e: 
        logger.error(f"Error listing directory {abs_folder_path_to_browse}: {e}")
        abort(500, "Error listing directory contents.")
    
    # For display, show the relative path from shared_space root
    current_display_folder = norm_folder if norm_folder else "Root"
    return render_template('directory.html', 
                           files=files_and_dirs, 
                           current_folder_display=current_display_folder,
                           current_folder_path=norm_folder, # For constructing links in template
                           parent_folder_link=parent_folder_link)


@app.route('/download/<path:filepath>')
def download_file_from_shared_space(filepath): # Renamed function
    logger = current_app.logger
    abs_shared_space_check = os.path.abspath(shared_space)

    # Normalize filepath carefully
    norm_filepath = os.path.normpath(filepath)
    # Prevent escaping shared_space
    if norm_filepath.startswith('/') or '..' in norm_filepath.split(os.sep):
        logger.warning(f"Invalid or disallowed file path traversal attempt for download: {filepath}")
        abort(400, "Invalid file path.")

    abs_file_to_download = os.path.abspath(os.path.join(abs_shared_space_check, norm_filepath))

    # Final check to ensure we are within the shared_space and it's a file
    if not abs_file_to_download.startswith(abs_shared_space_check):
        logger.warning(f"File download attempt outside shared space: {abs_file_to_download}")
        abort(403) # Forbidden

    if not os.path.isfile(abs_file_to_download):
        logger.warning(f"File not found for download: {abs_file_to_download} (relative: {norm_filepath})")
        abort(404)
    
    # send_from_directory needs the directory and the filename separately
    directory_containing_file = os.path.dirname(abs_file_to_download)
    base_filename = os.path.basename(abs_file_to_download)
    return send_from_directory(directory_containing_file, base_filename, as_attachment=True)

def get_file_list(folder_path_abs): 
    # folder_path_abs is assumed to be validated and safe already
    logger = current_app.logger
    items = []
    for item_name in os.listdir(folder_path_abs):
        item_abs_path = os.path.join(folder_path_abs, item_name)
        # Get path relative to shared_space for link generation
        item_rel_path = os.path.relpath(item_abs_path, shared_space)
        
        item_type = 'file' if os.path.isfile(item_abs_path) else 'folder' if os.path.isdir(item_abs_path) else 'unknown'
        if item_type != 'unknown':
            items.append({'name': item_name, 'type': item_type, 'path': item_rel_path})
    # Sort items: folders first, then files, both alphabetically
    items.sort(key=lambda x: (x['type'] != 'folder', x['name'].lower()))
    return items

# --- Main Execution (for direct run, not Gunicorn) ---
if __name__ == '__main__':
  # Logging is already configured by configure_logging(app)
  # Ensure log level is appropriate for direct run if different from env var default
  if os.environ.get('LOG_LEVEL') is None: # If no LOG_LEVEL env var
      app.logger.setLevel(logging.DEBUG) # Default to DEBUG for direct run
      logging.getLogger('app.yt-dlp').setLevel(logging.DEBUG)
      app.logger.info("Direct run: Log level set to DEBUG as LOG_LEVEL env var is not set.")
  
  port = int(os.environ.get('PORT', 5000))
  host = '0.0.0.0'
  
  # Pass the app's logger to WSGIServer for its own messages if desired
  # Otherwise, WSGIServer might use its own basic logging.
  # Gevent's WSGIServer can take a `log` argument which should be a Logger-like object.
  app.logger.info(f"Starting Gevent WSGIServer on {host}:{port}")
  http_server = WSGIServer((host, port), app, log=app.logger, error_log=app.logger) # Pass logger
  try:
      http_server.serve_forever()
  except KeyboardInterrupt:
      app.logger.info("Server shutting down due to KeyboardInterrupt.")
  except Exception as e:
      app.logger.critical(f"WSGIServer failed to start or crashed: {e}", exc_info=True)
