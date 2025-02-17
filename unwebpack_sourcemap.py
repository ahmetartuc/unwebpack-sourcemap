import argparse
import json
import os
import re
import string
import sys
from urllib.parse import urlparse
from unicodedata import normalize

import requests
from bs4 import BeautifulSoup, SoupStrainer

class SourceMapExtractor(object):
    """Primary SourceMapExtractor class. Feed this arguments."""

    _target = None
    _is_local = False
    _attempt_sourcemap_detection = False
    _output_directory = ""
    _target_extracted_sourcemaps = []

    _path_sanitiser = None

    def __init__(self, options):
        """Initialize the class."""
        if 'output_directory' not in options:
            raise SourceMapExtractorError("output_directory must be set in options.")
        else:
            self._output_directory = os.path.abspath(options['output_directory'])
            if not os.path.isdir(self._output_directory):
                if options['make_directory'] is True:
                    os.mkdir(self._output_directory)
                else:
                    raise SourceMapExtractorError("output_directory does not exist. Pass --make-directory to auto-make it.")

        self._path_sanitiser = PathSanitiser(self._output_directory)
        self.disable_verify_ssl = options['disable_ssl_verification']
        self._is_local = options['local']
        self._attempt_sourcemap_detection = options['detect']
        self._validate_target(options['uri_or_file'])

    def run(self):
        """Run extraction process."""
        if not self._is_local:
            if self._attempt_sourcemap_detection:
                detected_sourcemaps = self._detect_js_sourcemaps(self._target)
                for sourcemap in detected_sourcemaps:
                    self._parse_remote_sourcemap(sourcemap)
            else:
                self._parse_remote_sourcemap(self._target)
        else:
            self._parse_sourcemap(self._target)

    def _detect_js_sourcemaps(self, uri):
        """Pull HTML and attempt to find JS files, then read the JS files and look for sourceMappingURL."""
        remote_sourcemaps = []
        data, final_uri = self._get_remote_data(uri)

        print("Detecting sourcemaps in HTML at %s" % final_uri)
        script_strainer = SoupStrainer("script", src=True)
        try:
            soup = BeautifulSoup(data, "html.parser", parse_only=script_strainer)
        except:
            raise SourceMapExtractorError("Could not parse HTML at URI %s" % final_uri)

        for script in soup:
            source = script['src']
            parsed_uri = urlparse(source)
            next_target_uri = source if parsed_uri.scheme else urlparse(final_uri)._replace(path=source).geturl()

            js_data, last_target_uri = self._get_remote_data(next_target_uri)
            last_line = js_data.rstrip().split("\n")[-1]
            regex = r"\/\/\#\s*sourceMappingURL=(.*)$"
            matches = re.search(regex, last_line)
            if matches:
                asset = matches.group(1).strip()
                asset_uri = asset if urlparse(asset).scheme else urlparse(last_target_uri)._replace(path=os.path.dirname(urlparse(last_target_uri).path) + '/' + asset).geturl()
                print("Detected sourcemap at remote location %s" % asset_uri)
                remote_sourcemaps.append(asset_uri)

        return remote_sourcemaps

class SourceMapExtractorError(Exception):
    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A tool to extract code from Webpack sourcemaps. Turns black boxes into gray ones.")
    parser.add_argument("-l", "--local", action="store_true", default=False)
    parser.add_argument("-d", "--detect", action="store_true", default=False, help="Attempt to detect sourcemaps from JS assets in retrieved HTML.")
    parser.add_argument("--make-directory", action="store_true", default=False, help="Make the output directory if it doesn't exist.")
    parser.add_argument("--disable-ssl-verification", action="store_true", default=False, help="The script will not verify the site's SSL certificate.")
    parser.add_argument("uri_or_file", help="The target URI or file.")
    parser.add_argument("output_directory", help="Directory to output from sourcemap to.")

    if len(sys.argv) < 3:
        parser.print_usage()
        sys.exit(1)

    args = parser.parse_args()
    extractor = SourceMapExtractor(vars(args))
    extractor.run()
