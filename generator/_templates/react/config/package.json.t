---
to: ../generated/<%= dest %>/<%= name %>/package.json
force: true
---
{
  "name": "samples-js-react-<%= name %>",
  "version": "0.3.0",
  "private": true,
  "dependencies": {
    "@okta/okta-auth-js": "^5.0.0",
    "@okta/okta-react": "^6.0.0",
    <%- name === 'custom-login' ? `"@okta/okta-signin-widget": "^5.4.0",` : '' %>
    "colors": "^1.4.0",
    "dotenv": "^8.2.0",
    "react": "^17.0.1",
    "react-dom": "^17.0.1",
    "react-router-dom": "^5.2.0",
    "react-scripts": "^4.0.1",
    "semantic-ui-css": "^2.4.1",
    "semantic-ui-react": "^2.0.3",
    "text-encoding": "^0.7.0"
  },
  "scripts": {
    "start": "cross-env PORT=8080 react-app-rewired start",
    "build": "react-app-rewired build",
    "test": "react-scripts test --watchAll=false",
    "eject": "react-scripts eject",
    "lint": "eslint -c .eslintrc.json --ext .js --ext .jsx src/"
  },
  "devDependencies": {
    "h": "^1.0.0",
    "react-app-rewired": "^2.1.8",
    "source-map-loader": "^1.1.0",
    "eslint": "^7.12.1",
    "eslint-config-airbnb": "^18.2.0",
    "eslint-plugin-import": "^2.22.0",
    "eslint-plugin-jsx-a11y": "^6.3.1",
    "eslint-plugin-react": "^7.20.6",
    "eslint-plugin-react-hooks": "^4.1.1",
    "cross-env": "^7.0.3",
    "jest-watch-typeahead": "^0.6.4"
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ],
    "development": [
      "last 1 chrome version",
      "last 1 firefox version",
      "last 1 safari version"
    ]
  }
}
