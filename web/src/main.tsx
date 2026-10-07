import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "./index.css";
import { initTheme } from "./ui";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Certificates from "./pages/Certificates";
import CertificateDetail from "./pages/CertificateDetail";
import AcmeAccounts from "./pages/AcmeAccounts";
import DnsProviders from "./pages/DnsProviders";
import DeployTargets from "./pages/DeployTargets";
import Logs from "./pages/Logs";
import Settings from "./pages/Settings";

initTheme();

const qc = new QueryClient({
  defaultOptions: {
    queries: {
      // Views refresh from the SSE stream rather than on a timer, so there
      // is no polling interval here.
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

const router = createBrowserRouter([
  { path: "/login", element: <Login /> },
  { path: "/", element: <Dashboard /> },
  { path: "/certificates", element: <Certificates /> },
  { path: "/certificates/:id", element: <CertificateDetail /> },
  { path: "/acme-accounts", element: <AcmeAccounts /> },
  { path: "/dns-providers", element: <DnsProviders /> },
  { path: "/deploy-targets", element: <DeployTargets /> },
  { path: "/logs", element: <Logs /> },
  { path: "/settings", element: <Settings /> },
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </React.StrictMode>,
);
