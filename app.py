import functools
import logging
import traceback
import sys
from flask import Flask, Blueprint, current_app, jsonify, request, redirect, abort, Response # Added Response for text
from io import BytesIO
# Grouped Flask imports
from flask import render_template, send_from_directory, url_for,send_file
import os # Ensure os is imported for os.environ.get
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

# --- Your existing get_videos function (NO CHANGES HERE based on your request) ---
def get_videos(url, extra_params):
  '''
    Get a list with a dict for every video founded
    '''
  # --- START: TEMPORARY DEBUG LOG to check environment variable (from previous version) ---
  # This log will still appear in your server logs, not on the webpage.
  retrieved_cookie_content_from_env = os.environ.get('YOUTUBE_COOKIES_CONTENT')
  if retrieved_cookie_content_from_env:
      current_app.logger.info(f"DEBUG (in get_videos): YOUTUBE_COOKIES_CONTENT IS SET. Length: {len(retrieved_cookie_content_from_env)}. First 100 chars: '{retrieved_cookie_content_from_env[:100]}'")
  else:
      current_app.logger.warning("DEBUG (in get_videos): YOUTUBE_COOKIES_CONTENT IS NOT SET or is empty in the environment.")
  # --- END: TEMPORARY DEBUG LOG ---

  ydl_params = {
      'format': 'best',
      'cachedir': False,
      'verbose': False, 
      'logger': current_app.logger.getChild('yt-dlp'),
      'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36'
  }
  
  temp_cookie_file_path = None 
  
  cookie_content_env = retrieved_cookie_content_from_env # Use the one retrieved for logging
  if cookie_content_env:
      try:
          with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8') as tmpfile:
              tmpfile.write(cookie_content_env)
              temp_cookie_file_path = tmpfile.name
          ydl_params['cookies'] = temp_cookie_file_path
          current_app.logger.info(f"Using cookies from YOUTUBE_COOKIES_CONTENT environment variable via temp file: {temp_cookie_file_path}")
      except Exception as e:
          current_app.logger.error(f"Failed to create or use temporary cookie file from YOUTUBE_COOKIES_CONTENT: {e}")
          if temp_cookie_file_path and os.path.exists(temp_cookie_file_path):
              try: os.remove(temp_cookie_file_path)
              except OSError: pass 
          temp_cookie_file_path = None 
  
  if 'cookies' not in ydl_params:
      cookies_path = current_app.config.get('/cookies.txt') 
      if cookies_path:
          ydl_params['cookies'] = cookies_path 
          current_app.logger.info(f"Using cookies from Flask config key '/cookies.txt' with path: {cookies_path}")
  
  if 'cookies' not in ydl_params:
      current_app.logger.warning("No cookies configured via YOUTUBE_COOKIES_CONTENT or Flask config. YouTube may require authentication.")
  
  ydl_params.update(extra_params)
  ydl = SimpleYDL(ydl_params)
  
  res = None 
  try:
      res = ydl.extract_info(url, download=False)
  finally:
      if temp_cookie_file_path and os.path.exists(temp_cookie_file_path):
          try:
              os.remove(temp_cookie_file_path)
              current_app.logger.info(f"Removed temporary cookie file (from env var): {temp_cookie_file_path}")
          except OSError as e_remove:
              current_app.logger.error(f"Error removing temporary cookie file {temp_cookie_file_path}: {e_remove}")
  return res
# --- END of get_videos function ---

def flatten_result(result):
  # Safety for None result
  if result is None:
    current_app.logger.warning("flatten_result received None, returning empty list.")
    return []
  r_type = result.get('_type', 'video')
  if r_type == 'video':
    videos = [result]
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
    return jsonify({'error': f"An unexpected error occurred: {str(e)}"}), 500
  
  if result_data is None:
      current_app.logger.error(f"get_result() returned None for URL: {request.args.get('url')}. Cannot build response.")
      return jsonify({'error': 'Failed to retrieve video information.'}), 500

  url = request.args['url']
  key = 'info'
  if query_bool(request.args.get('flatten'), 'flatten', False):
    final_data = flatten_result(result_data) 
    key = 'videos'
  else: final_data = result_data
  return jsonify({'url': url, key: final_data})

@route_api('play')
@set_access_control # Added missing decorator, assuming it was intended like other API routes
def play():
  try: result_data = get_result()
  except Exception as e:
    if isinstance(e, (yt_dlp.utils.DownloadError, yt_dlp.utils.ExtractorError, WrongParameterTypeError)): raise
    current_app.logger.error(f"Unexpected error in /play route during get_result: {e}\n{traceback.format_exc()}")
    return jsonify({'error': f"An unexpected error occurred: {str(e)}"}), 500

  if result_data is None:
      current_app.logger.error("get_result() returned None for /play endpoint. Cannot redirect.")
      return jsonify({'error': 'Failed to retrieve video information for play.'}), 500
  
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
  return jsonify({'yt-dlp': yt_dlp_version, 'yt-dlp-api-server': "0.3"}) # Reverted version string


app = Flask(__name__)

# --- START: NEW DEBUG ROUTE TO DISPLAY COOKIE ENV VAR ---
@app.route('/debug/view-cookies-env', methods=['GET'])
def view_cookies_env():
    """
    SECURITY WARNING: This endpoint displays sensitive cookie information.
    It should ONLY be used for temporary debugging by the administrator
    and MUST be removed or secured after use.
    """
    cookie_content = os.environ.get('YOUTUBE_COOKIES_CONTENT')
    if cookie_content:
        # Return as plain text, preserving line breaks
        # Using <pre> tags for basic HTML formatting if viewed in a browser
        html_escaped_content = cookie_content.replace('&', '&').replace('<', '<').replace('>', '>')
        return Response(f"<pre>{html_escaped_content}</pre>", mimetype='text/html')
    else:
        return Response("Environment variable YOUTUBE_COOKIES_CONTENT is not set or is empty.", mimetype='text/plain')
# --- END: NEW DEBUG ROUTE ---


app.register_blueprint(api)

cfg_file_path_original = '../application.cfg' 
app.config.from_pyfile(cfg_file_path_original, silent=True)
# Optional: Log if config was loaded (after app.logger is configured)
# This needs app.logger to be configured, which happens in `if __name__ == '__main__'`
# or if Gunicorn configures it. For now, this might not log if run via Gunicorn
# without specific Gunicorn logger setup linked to app.logger.

@app.route('/api', methods=['GET']) 
def index(): return "Hello, World!"

# --- Directory browsing/file serving part ---
home_directory = os.path.expanduser("~") 
shared_space = os.path.join(os.path.dirname(app.instance_path), os.sep, '') 
# Consider making shared_space configurable via env var or app.config for Railway.

@app.route('/directory/')
@app.route('/directory/<path:folder>/')
def directory(folder=''):
    logger = current_app.logger # Use logger
    # Basic check for shared_space validity
    abs_shared_space_check = os.path.abspath(shared_space)
    if not os.path.isdir(abs_shared_space_check):
        logger.error(f"Shared space directory '{shared_space}' (resolved to {abs_shared_space_check}) not found or not a directory.")
        abort(500, "Server file storage is not correctly configured.")

    folder_path = os.path.join(shared_space, folder)
    abs_folder_path = os.path.abspath(folder_path)
    if not abs_folder_path.startswith(abs_shared_space_check) or not os.path.isdir(abs_folder_path):
        logger.warning(f"Dir access denied/not found: {folder_path} (resolved: {abs_folder_path})")
        abort(404)
    try: files = get_file_list(abs_folder_path) 
    except OSError as e: 
        logger.error(f"Error listing directory {abs_folder_path}: {e}")
        abort(500)
    return render_template('directory.html', files=files, current_folder=folder_path)

@app.route('/directory/<path:folder>/<filename>')
def download_file(folder, filename):
    logger = current_app.logger
    abs_shared_space_check = os.path.abspath(shared_space)
    if not os.path.isdir(abs_shared_space_check):
        logger.error(f"Shared space directory '{shared_space}' (resolved to {abs_shared_space_check}) not found for download.")
        abort(500, "Server file storage is not correctly configured.")
        
    folder_path = os.path.join(shared_space, folder)
    abs_file_path = os.path.abspath(os.path.join(folder_path, filename))
    if not abs_file_path.startswith(abs_shared_space_check) or not os.path.isfile(abs_file_path):
        logger.warning(f"File download denied/not found: {os.path.join(folder, filename)} (resolved: {abs_file_path})")
        abort(404)
    return send_from_directory(os.path.abspath(folder_path), filename, as_attachment=True)

def get_file_list(folder_path_abs): 
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

# Logging configuration for `if __name__ == '__main__'`
if __name__ == '__main__':
  # --- Enhanced Logging Configuration for direct run ---
  LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
  logging.basicConfig(stream=sys.stdout, level=logging.INFO, format=LOG_FORMAT)

  flask_log_level_str = os.environ.get('FLASK_LOG_LEVEL', app.config.get('LOG_LEVEL', 'INFO')).upper()
  flask_log_level = getattr(logging, flask_log_level_str, logging.INFO)
  app.logger.setLevel(flask_log_level)
  
  if not app.logger.handlers:
      stdout_handler = logging.StreamHandler(sys.stdout)
      stdout_handler.setFormatter(logging.Formatter(LOG_FORMAT))
      app.logger.addHandler(stdout_handler)
      app.logger.propagate = False 
  
  app.logger.info(f"Flask app logger initialized for direct run. Effective level: {logging.getLevelName(app.logger.getEffectiveLevel())}")
  # --- END Logging Configuration ---
  
  app.config["CACHE_TYPE"] = "null" 
  port = int(os.environ.get('PORT', 5000))
  host = '0.0.0.0'
  app.logger.info(f"Starting WSGIServer (gevent) on {host}:{port}")
  http_server = WSGIServer((host, port), app)
  try: http_server.serve_forever()
  except KeyboardInterrupt: app.logger.info("Server shutting down.")
