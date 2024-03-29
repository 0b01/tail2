process.env.NODE_ENV = 'development';

const fs = require('fs-extra');
const paths = require('react-scripts/config/paths');
const webpack = require('webpack');
const config = require('react-scripts/config/webpack.config.js')("development");
// console.log(config);

// removes react-dev-utils/webpackHotDevClient.js at first in the array
// config.entry.shift();

config.output.publicPath = process.env.PUBLIC_URL;

webpack(config).watch({}, (err, stats) => {
  if (err) {
    console.error(err);
  } else {
    copyPublicFolder();
  }
  console.error(stats.toString({
    chunks: false,
    colors: true
  }));
});

function copyPublicFolder() {
  console.log(paths);
  fs.copySync(paths.appPublic, paths.appBuild, {
    dereference: true,
    filter: file => file !== paths.appHtml
  });
  fs.copySync(paths.appBuild, process.env.BUILD_PATH, {
    dereference: true,
  });
}