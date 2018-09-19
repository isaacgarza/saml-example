// Karma configuration file, see link for more information
// https://karma-runner.github.io/1.0/config/configuration-file.html
const path = require('path');
module.exports = function (config) {
  config.set({
    basePath: '',
    browserDisconnectTimeout: 99999,
    browserNoActivityTimeout: 99999,
    frameworks: ['jasmine', '@angular/cli'],
    plugins: [
      require('karma-jasmine'),
      require('karma-chrome-launcher'),
      require('karma-phantomjs-launcher'),
      require('karma-jasmine-html-reporter'),
      require('karma-html-reporter'),
      require('karma-junit-reporter'),
      require('karma-spec-reporter'),
      require('karma-coverage-istanbul-reporter'),
      require('@angular/cli/plugins/karma')
    ],
    client:{
      clearContext: false // leave Jasmine Spec Runner output visible in browser
    },
    coverageIstanbulReporter: {
      reports: ['html', 'lcovonly', 'cobertura', 'text-summary'],
      fixWebpackSourcePaths: true,
      dir: path.join(__dirname, 'reports'),
      'report-config': {
        html: {
          subdir: 'coverage'
        }
      }
    },
    angularCli: {
      environment: 'dev'
    },
    exclude: [],
    files: [],
    reporters:
      config.angularCli && config.angularCli.codeCoverage
        ? ['spec', 'html', 'coverage-istanbul', 'junit']
        : ['spec', 'html', 'junit'],
    htmlReporter: {
      outputDir: 'reports/unit-test',
      templatePath: null,
      focusOnFailures: false,
      namedFiles: true,
      pageTitle: 'Web Platform Unit Test Report',
      urlFriendlyName: true,
      reportName: 'web-unit-test-report'
    },
    junitReporter: {
      outputDir: 'reports/unit-test',
      outputFile: 'web-unit-test-report.xml',
      suite: 'Web-Platform',
      useBrowserName: false,
      nameFormatter: undefined,
      classNameFormatter: undefined,
      properties: {}
    },
    webpack: { node: { fs: 'empty'} },
    //reporters: ['progress', 'kjhtml'],
    port: 9876,
    colors: true,
    logLevel: config.LOG_INFO,
    autoWatch: true,
    browsers: ['PhantomJS'],
    singleRun: false
  });
};
