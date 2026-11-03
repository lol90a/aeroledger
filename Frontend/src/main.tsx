
  // First, and it has to stay first: the Solana libraries read the `Buffer`
  // global at import time, so the polyfill must be evaluated before anything
  // that imports them. See src/polyfills.ts.
  import "./polyfills";

  import { createRoot } from "react-dom/client";
  import App from "./app/App.tsx";
  import "./styles/index.css";

  createRoot(document.getElementById("root")!).render(<App />);
  