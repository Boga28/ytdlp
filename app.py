import functools
import logging
import traceback
import sys
from flask import Flask, Blueprint, current_app, jsonify, request, redirect, abort
from io import BytesIO
from flask import Flask, render_template, send_from_directory, url_for,send_file,request,jsonify
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
  cookie_content_env = os.environ.get('YOUTUBE_COOKIES_CONTENT')
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
          current_app.logger.error(f"Failed to create or use temporary cookie file from YOUTUBE_COOKIES_CONTENT: {e}")
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
        for r in result['entries']:
            # Added safety check for r being None
            if r:
                videos.extend(flatten_result(r))
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
  logging.error(traceback.format_exc())
  result = jsonify({'error': str(error)})
  result.status_code = 500
  return result

class WrongParameterTypeError(ValueError):
  def __init__(self, value, type, parameter):
    message = '"{}" expects a {}, got "{}"'.format(parameter, type, value)
    super(WrongParameterTypeError, self).__init__(message)

@api.errorhandler(WrongParameterTypeError)
def handle_wrong_parameter(error):
  logging.error(traceback.format_exc())
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
  url = request.args['url']
  extra_params = {}
  for k, v in request.args.items():
    if k in ALLOWED_EXTRA_PARAMS:
      convertf = ALLOWED_EXTRA_PARAMS[k]
      if convertf == bool:
        convertf = lambda x: query_bool(x, k)
      elif convertf == list:
        convertf = lambda x: x.split(',')
      extra_params[k] = convertf(v)
  return get_videos(url, extra_params)

@route_api('info')
@set_access_control
def info():
  url = request.args['url']
  result = get_result()
  key = 'info'
  if query_bool(request.args.get('flatten'), 'flatten', False):
    result = flatten_result(result)
    key = 'videos'
  # Safety check for result before packaging
  if result is None:
      current_app.logger.error(f"get_result() returned None for URL: {url}. Cannot build response.")
      return jsonify({'error': 'Failed to retrieve video information.'}), 500
  result = {
      'url': url,
      key: result,
  }
  return jsonify(result)

@route_api('play')
def play():
  result = get_result()
  # Safety check for result before flattening and accessing
  if result is None:
      current_app.logger.error("get_result() returned None for /play endpoint. Cannot redirect.")
      return jsonify({'error': 'Failed to retrieve video information for play.'}), 500
  
  flat_result = flatten_result(result)
  # Safety check after flattening
  if not flat_result or not isinstance(flat_result, list) or not flat_result[0] or 'url' not in flat_result[0]:
      current_app.logger.error(f"Could not extract a playable URL. Flattened result: {flat_result}")
      return jsonify({'error': 'Could not extract a playable URL from the video information.'}), 404
      
  return redirect(flat_result[0]['url'])

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
      'yt-dlp-api-server': 0.3, # Version of the API server code itself
  }
  return jsonify(result)

app = Flask(__name__)
app.register_blueprint(api)

# Original configuration loading
# This assumes application.cfg is one directory level above the app.py file.
# If app.py is at the root, this should be 'application.cfg'
cfg_file_path_original = '../application.cfg'
# More robust way to define path to application.cfg relative to app.py:
# If app.py is /path/to/project/src/app.py and cfg is /path/to/project/application.cfg
# current_dir = os.path.dirname(os.path.abspath(__file__))
# cfg_file_path = os.path.join(current_dir, '..', 'application.cfg')
# However, sticking to user's original:
app.config.from_pyfile(cfg_file_path_original, silent=True)

@app.route('/api', methods=['GET']) # This route is fine
def index():
  return "Hello, World!"


# --- The following directory browsing/file serving part is kept as is from your original code ---
home_directory = os.path.expanduser("~")
# Note: app.instance_path might not be what you expect on Railway for shared storage.
# It's often a folder named 'instance' next to your app package.
# Consider using a path relative to your project root or an env var for shared_space on Railway.
shared_space = os.path.join(os.path.dirname(app.instance_path), os.sep, '')

#import getpass
#username = getpass.getuser() #current username
#shared_space = 'C:\\Users\\{}\\Downloads'.format(username) #Shared folder location. customize it on your need. 

@app.route('/directory/')
@app.route('/directory/<path:folder>/')
def directory(folder=''):
    folder_path = os.path.join(shared_space, folder)
    # Security: Ensure folder_path is within shared_space and exists
    abs_shared_space = os.path.abspath(shared_space)
    abs_folder_path = os.path.abspath(folder_path)
    if not abs_folder_path.startswith(abs_shared_space) or not os.path.isdir(abs_folder_path):
        current_app.logger.warning(f"Access denied or directory not found: {folder_path}")
        abort(404)
    try:
        files = get_file_list(abs_folder_path) # Pass absolute path
    except OSError: # get_file_list might raise OSError if os.listdir fails
        current_app.logger.error(f"Error listing directory: {abs_folder_path}")
        abort(500)
    return render_template('directory.html', files=files, current_folder=folder_path) # Pass relative path for template

@app.route('/directory/<path:folder>/<filename>')
def download_file(folder, filename):
    folder_path = os.path.join(shared_space, folder)
    # Security: Ensure file path is within shared_space
    abs_shared_space = os.path.abspath(shared_space)
    abs_file_path = os.path.abspath(os.path.join(folder_path, filename))
    if not abs_file_path.startswith(abs_shared_space) or not os.path.isfile(abs_file_path):
        current_app.logger.warning(f"Access denied or file not found for download: {os.path.join(folder, filename)}")
        abort(404)
    # send_from_directory expects the directory part, not the full path to the file
    # and the directory must be absolute or relative to app root.
    # To be safe, pass the absolute directory.
    return send_from_directory(os.path.abspath(folder_path), filename)

def get_file_list(folder_path_abs): # Expects absolute path
    items = []
    # Ensure folder_path_abs is a directory before listing
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

# ... (rest of your app.py code) ...

if __name__ == '__main__':
  # Configure basic logging first (good for non-Flask specific logs)
  logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

  # Explicitly set Flask's app logger level
  # This needs to happen AFTER `app = Flask(__name__)` is defined
  # Get LOG_LEVEL from app.config (e.g., set in application.cfg or an env var like FLASK_LOG_LEVEL)
  # Default to INFO if not set.
  flask_log_level_str = app.config.get('LOG_LEVEL', os.environ.get('FLASK_LOG_LEVEL', 'INFO')).upper()
  flask_log_level = getattr(logging, flask_log_level_str, logging.INFO)
  
  app.logger.setLevel(flask_log_level)
  
  # Also set the logger for 'yt-dlp' if you want to control its verbosity through Flask's logger
  # (though yt-dlp's own 'verbose' param is more direct for its internal messages)
  # logging.getLogger('yt-dlp').setLevel(flask_log_level) # Optional

  # Also set the handler for app.logger to ensure it outputs where Gunicorn can pick it up (stdout)
  # Gunicorn usually handles this, but being explicit can help.
  if not app.logger.handlers:
      handler = logging.StreamHandler(sys.stdout)
      handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
      app.logger.addHandler(handler)
  
  app.logger.info(f"Flask app logger initialized with level: {logging.getLevelName(app.logger.getEffectiveLevel())}")


  app.config["CACHE_TYPE"] = "null" # Usually for development
  
  port = int(os.environ.get('PORT', 5000))
  host = '0.0.0.0'
  
  # Use app.logger for this message too
  app.logger.info(f"Starting WSGIServer on {host}:{port}")
  http_server = WSGIServer((host, port), app)
  try:
    http_server.serve_forever()
  except KeyboardInterrupt:
    app.logger.info("Server shutting down.")
