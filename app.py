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
from gevent.pywsgi import WSGIServer # Note: Gunicorn uses its own workers, gevent might be for direct run
import yt_dlp
from yt_dlp.version import __version__ as yt_dlp_version

# --- START: Global Logging Configuration (runs at import time) ---
# This basicConfig will apply to the root logger.
# Flask app's logger will be configured after 'app' is created.
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format=LOG_FORMAT)
# --- END: Global Logging Configuration ---


if not hasattr(sys.stderr, 'isatty'):
  sys.stderr.isatty = lambda: False

class SimpleYDL(yt_dlp.YoutubeDL):
  def __init__(self, *args, **kargs):
    super(SimpleYDL, self).__init__(*args, **kargs)
    self.add_default_info_extractors()

def get_videos(url, extra_params):
  # Use current_app.logger here as it's called within a request context
  logger = current_app.logger 

  # --- START: TEMPORARY DEBUG LOG to check environment variable ---
  retrieved_cookie_content_from_env = os.environ.get('YOUTUBE_COOKIES_CONTENT')
  if retrieved_cookie_content_from_env:
      logger.info(f"DEBUG: YOUTUBE_COOKIES_CONTENT IS SET. Length: {len(retrieved_cookie_content_from_env)}. First 100 chars: '{retrieved_cookie_content_from_env[:100]}'")
  else:
      logger.warning("DEBUG: YOUTUBE_COOKIES_CONTENT IS NOT SET or is empty in the environment.")
  # --- END: TEMPORARY DEBUG LOG ---

  ydl_params = {
      'format': 'best',
      'cachedir': False,
      'verbose': False, 
      'logger': logger.getChild('yt-dlp'), # Pass the correct logger
      'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36'
  }
  
  temp_cookie_file_path = None 
  cookie_content_env = retrieved_cookie_content_from_env 
  if cookie_content_env:
      try:
          with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8') as tmpfile:
              tmpfile.write(cookie_content_env)
              temp_cookie_file_path = tmpfile.name
          ydl_params['cookies'] = temp_cookie_file_path
          logger.info(f"Using cookies from YOUTUBE_COOKIES_CONTENT environment variable via temp file: {temp_cookie_file_path}")
      except Exception as e:
          logger.error(f"Failed to create or use temporary cookie file from YOUTUBE_COOKIES_CONTENT: {e} - {traceback.format_exc()}")
          if temp_cookie_file_path and os.path.exists(temp_cookie_file_path):
              try: os.remove(temp_cookie_file_path)
              except OSError: pass 
          temp_cookie_file_path = None 
  
  if 'cookies' not in ydl_params:
      cookies_path = current_app.config.get('/cookies.txt') 
      if cookies_path:
          ydl_params['cookies'] = cookies_path 
          logger.info(f"Using cookies from Flask config key '/cookies.txt' with path: {cookies_path}")
  
  if 'cookies' not in ydl_params:
      logger.warning("No cookies configured via YOUTUBE_COOKIES_CONTENT or Flask config. YouTube may require authentication.")
  
  ydl_params.update(extra_params)
  ydl = SimpleYDL(ydl_params)
  
  res = None 
  try:
      res = ydl.extract_info(url, download=False)
  finally:
      if temp_cookie_file_path and os.path.exists(temp_cookie_file_path):
          try:
              os.remove(temp_cookie_file_path)
              logger.info(f"Removed temporary cookie file (from env var): {temp_cookie_file_path}")
          except OSError as e_remove:
              logger.error(f"Error removing temporary cookie file {temp_cookie_file_path}: {e_remove}")
  return res

def flatten_result(result):
  logger = current_app.logger # Use current_app.logger
  if result is None:
    logger.warning("flatten_result received None, returning empty list.")
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
    logger.warning(f"flatten_result encountered an unrecognized _type: {r_type}")
    videos = []
  return videos

api = Blueprint('api', __name__)

# Error handlers use current_app.logger, which is fine as they run in request context
@api.errorhandler(yt_dlp.utils.DownloadError)
@api.errorhandler(yt_dlp.utils.ExtractorError)
def handle_youtube_dl_error(error):
  current_app.logger.error(f"yt-dlp Download/Extractor Error: {str(error)}\n{traceback.format_exc()}")
  return jsonify({'error': str(error)}), 500

class WrongParameterTypeError(ValueError):
  def __init__(self, value, type, parameter):
    super().__init__(f'"{parameter}" expects a {type}, got "{value}"')

@api.errorhandler(WrongParameterTypeError)
def handle_wrong_parameter(error):
  current_app.logger.error(f"Wrong Parameter Type Error: {str(error)}\n{traceback.format_exc()}")
  return jsonify({'error': str(error)}), 400

@api.before_request # Runs in request context
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
}

def get_result(): # Runs in request context
  logger = current_app.logger
  if 'url' not in request.args:
      logger.error("API request made without 'url' parameter.")
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
          logger.error(f"Could not convert parameter '{k}' with value '{v}' using {convertf.__name__}: {e} - {traceback.format_exc()}")
          raise WrongParameterTypeError(v, str(convertf), k) # Use str(convertf) for type name
    else:
        logger.debug(f"Ignoring unknown query parameter: {k}")
  return get_videos(url, extra_params)

@route_api('info')
@set_access_control
def info(): # Runs in request context
  logger = current_app.logger
  try: result_data = get_result()
  except Exception as e: 
    if isinstance(e, (yt_dlp.utils.DownloadError, yt_dlp.utils.ExtractorError, WrongParameterTypeError)): raise 
    logger.error(f"Unexpected error in /info route during get_result: {e}\n{traceback.format_exc()}")
    return jsonify({'error': f"An unexpected error occurred: {str(e)}"}), 500
  
  if result_data is None:
      logger.error(f"get_result() returned None for URL: {request.args.get('url')}. Cannot build response.")
      return jsonify({'error': 'Failed to retrieve video information.'}), 500

  url = request.args['url']
  key = 'info'
  if query_bool(request.args.get('flatten'), 'flatten', False):
    final_data = flatten_result(result_data) 
    key = 'videos'
  else: final_data = result_data
  return jsonify({'url': url, key: final_data})

@route_api('play') # Runs in request context
def play():
  logger = current_app.logger
  try: result_data = get_result()
  except Exception as e:
    if isinstance(e, (yt_dlp.utils.DownloadError, yt_dlp.utils.ExtractorError, WrongParameterTypeError)): raise
    logger.error(f"Unexpected error in /play route during get_result: {e}\n{traceback.format_exc()}")
    return jsonify({'error': f"An unexpected error occurred: {str(e)}"}), 500

  if result_data is None:
      logger.error("get_result() returned None for /play endpoint. Cannot redirect.")
      return jsonify({'error': 'Failed to retrieve video information for play.'}), 500
  
  flat_results = flatten_result(result_data) 
  if not flat_results or not isinstance(flat_results, list) or not flat_results[0] or 'url' not in flat_results[0]:
      logger.error(f"Could not extract a playable URL. Flattened result: {flat_results}")
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
  return jsonify({'yt-dlp': yt_dlp_version, 'yt-dlp-api-server': "0.3-debug-logging"})

# --- Flask App Initialization and Configuration (runs at import time by Gunicorn) ---
app = Flask(__name__)

# Configure Flask app's logger specifically (Gunicorn friendly)
# Get log level from environment, then app.config (if set before here), default to INFO.
gunicorn_logger = logging.getLogger('gunicorn.error')
app.logger.handlers = gunicorn_logger.handlers # Use Gunicorn's handlers
app.logger.setLevel(os.environ.get('FLASK_LOG_LEVEL', app.config.get('LOG_LEVEL', 'INFO')).upper())
# If you want to be absolutely sure even if Gunicorn's handlers aren't set:
if not app.logger.handlers and not gunicorn_logger.handlers : # Check gunicorn_logger.handlers too
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    app.logger.addHandler(stdout_handler)

app.logger.info(f"Flask app '{__name__}' logger initialized. Effective level: {logging.getLevelName(app.logger.getEffectiveLevel())}")
# --- End Flask App Logger Configuration ---


app.register_blueprint(api)

cfg_file_path_original = '../application.cfg' 
app.config.from_pyfile(cfg_file_path_original, silent=True)
# Log if config was loaded or not
if app.config.get('SERVER_NAME'): # Check an arbitrary key that might be in a config
    app.logger.info(f"Loaded config from {cfg_file_path_original} (or it was silent and empty).")
else:
    app.logger.info(f"Config file {cfg_file_path_original} not found or empty, using defaults/env vars.")


@app.route('/api', methods=['GET']) 
def index(): return "Hello, World!"

# --- Directory browsing/file serving part ---
# This section uses current_app.logger and current_app.config, so it's fine here.
# But the definition of `shared_space` at the global level using `app.instance_path` 
# before `app` is fully defined by Gunicorn could be an issue.
# Let's defer its definition or make it configurable.

# A better way for shared_space:
SHARED_SPACE_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'downloads_default')
# Get from env, then app.config, then default. `app` object is available here.
shared_space = os.environ.get('SHARED_DOWNLOAD_PATH', app.config.get('SHARED_DOWNLOAD_PATH', SHARED_SPACE_DEFAULT))

# Ensure shared_space exists (optional, good practice)
if not os.path.exists(shared_space):
    try:
        os.makedirs(shared_space, exist_ok=True)
        app.logger.info(f"Shared space directory ensured/created at: {shared_space}")
    except OSError as e:
        app.logger.error(f"Could not create shared_space directory {shared_space}: {e}")
        # Decide if this is a fatal error for your app
        # shared_space = None # Or some other fallback if creation fails

@app.route('/directory/')
@app.route('/directory/<path:folder>/')
def directory(folder=''):
    logger = current_app.logger
    if not shared_space or not os.path.isdir(os.path.abspath(shared_space)):
        logger.error(f"Shared space '{shared_space}' is not configured or not a directory.")
        abort(500, description="Server file storage is not configured.")

    folder_path = os.path.join(shared_space, folder)
    abs_shared_space = os.path.abspath(shared_space)
    abs_folder_path = os.path.abspath(folder_path)
    if not abs_folder_path.startswith(abs_shared_space) or not os.path.isdir(abs_folder_path):
        logger.warning(f"Dir access denied/not found: {folder_path} (resolved: {abs_folder_path})")
        abort(404)
    try: files = get_file_list(abs_folder_path) 
    except OSError as e: 
        logger.error(f"Error listing directory {abs_folder_path}: {e}")
        abort(500)
    return render_template('directory.html', files=files, current_folder=folder) 

@app.route('/directory/<path:folder>/<filename>')
def download_file(folder, filename):
    logger = current_app.logger
    if not shared_space or not os.path.isdir(os.path.abspath(shared_space)):
        logger.error(f"Shared space '{shared_space}' not configured for download.")
        abort(500, description="Server file storage not configured.")

    folder_path = os.path.join(shared_space, folder)
    abs_shared_space = os.path.abspath(shared_space)
    abs_file_path = os.path.abspath(os.path.join(folder_path, filename))
    if not abs_file_path.startswith(abs_shared_space) or not os.path.isfile(abs_file_path):
        logger.warning(f"File download denied/not found: {os.path.join(folder, filename)} (resolved: {abs_file_path})")
        abort(404)
    return send_from_directory(os.path.abspath(folder_path), filename, as_attachment=True)

def get_file_list(folder_path_abs): # Expects absolute path
    logger = current_app.logger
    items = []
    if not os.path.isdir(folder_path_abs):
        logger.error(f"get_file_list called with non-directory: {folder_path_abs}")
        raise OSError(f"Not a directory: {folder_path_abs}")
    for item in os.listdir(folder_path_abs):
        item_path = os.path.join(folder_path_abs, item)
        if os.path.isfile(item_path): items.append({'name': item, 'type': 'file'})
        elif os.path.isdir(item_path): items.append({'name': item, 'type': 'folder'})
    return items

# The `if __name__ == '__main__':` block is for direct execution (python app.py)
# Gunicorn will not run this block. WSGIServer from gevent is used here.
# If using Gunicorn, Gunicorn itself is the WSGI server.
if __name__ == '__main__':
  # This logging setup is for when running directly with `python app.py`
  # The global basicConfig and the app.logger setup above will handle Gunicorn.
  # However, we can re-affirm the app.logger level here if desired for direct run.
  
  # app.logger level should already be set from above when app = Flask() was hit.
  # We can add a handler here specifically for direct run if Gunicorn's handlers aren't present.
  if not app.logger.handlers: # Or check a specific flag if it was setup for Gunicorn
        main_handler = logging.StreamHandler(sys.stdout)
        main_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        app.logger.addHandler(main_handler)
        app.logger.propagate = False # Avoid duplicates if root logger also has handler

  app.logger.info(f"Running Flask app directly (not via Gunicorn import). Logger level: {logging.getLevelName(app.logger.getEffectiveLevel())}")
  
  app.config["CACHE_TYPE"] = "null" 
  port = int(os.environ.get('PORT', 5000))
  host = '0.0.0.0'
  app.logger.info(f"Starting gevent WSGIServer on {host}:{port}")
  http_server = WSGIServer((host, port), app)
  try: http_server.serve_forever()
  except KeyboardInterrupt: app.logger.info("Server shutting down.")
