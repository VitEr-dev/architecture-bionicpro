import React from 'react';
import { ReactKeycloakProvider } from '@react-keycloak/web';
import Keycloak from 'keycloak-js';
import ReportPage from './components/ReportPage';

const getRequiredEnv = (name: string): string => {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required env var: ${name}`);
  return value;
};

const keycloak = new Keycloak({
  url: getRequiredEnv('REACT_APP_KEYCLOAK_URL'),
  realm: getRequiredEnv('REACT_APP_KEYCLOAK_REALM'),
  clientId: getRequiredEnv('REACT_APP_KEYCLOAK_CLIENT_ID')
});

const App: React.FC = () => {
  return (
    <ReactKeycloakProvider
      authClient={keycloak}
      initOptions={{
        onLoad: 'login-required',
        pkceMethod: 'S256',
        checkLoginIframe: false,
        flow: 'standard',
        responseType: 'code'
      }}
    >
      <ReportPage />
    </ReactKeycloakProvider>
  );
};

export default App;