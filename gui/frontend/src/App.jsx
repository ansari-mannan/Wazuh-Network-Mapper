import React, { useCallback, useEffect, useState } from "react";
import Toolbar from "./components/Toolbar.jsx";
import TopologyView from "./components/TopologyView.jsx";
import DeviceDetail from "./components/DeviceDetail.jsx";
import { getConfig, getGraph, getScanStatus, startScan } from "./api.js";

export default function App() {
  const [graph, setGraph] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [community, setCommunity] = useState("");
  const [loadError, setLoadError] = useState(null);
  const [scanState, setScanState] = useState("idle"); // idle | running | done | error
  const [scanError, setScanError] = useState(null);

  // Pre-fill the community input from the backend default.
  useEffect(() => {
    getConfig().then((c) => setCommunity(c.community)).catch(() => {});
  }, []);

  const loadGraph = useCallback(async () => {
    setLoadError(null);
    try {
      setGraph(await getGraph());
    } catch (e) {
      setLoadError(e.message);
    }
  }, []);

  // Load the current graph on first mount so the canvas isn't empty.
  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  const runScan = useCallback(async () => {
    setScanError(null);
    setScanState("running");
    try {
      await startScan(community);
    } catch (e) {
      setScanState("error");
      setScanError(e.message);
      return; // existing graph stays on screen
    }
    // Poll status until the async scan finishes. On success refetch the graph;
    // on error surface the message and KEEP the currently displayed graph.
    const poll = setInterval(async () => {
      try {
        const s = await getScanStatus();
        if (s.status === "done") {
          clearInterval(poll);
          await loadGraph();
          setScanState("done");
          setTimeout(() => setScanState("idle"), 2500);
        } else if (s.status === "error") {
          clearInterval(poll);
          setScanState("error");
          setScanError(s.error || "scan failed");
        }
      } catch (e) {
        clearInterval(poll);
        setScanState("error");
        setScanError(e.message);
      }
    }, 1000);
  }, [community, loadGraph]);

  const selectedNode =
    graph && selectedId ? graph.nodes.find((n) => n.node_id === selectedId) : null;

  return (
    <div className="app">
      <Toolbar
        community={community}
        setCommunity={setCommunity}
        onLoad={loadGraph}
        onScan={runScan}
        scanState={scanState}
        scanError={scanError}
        loadError={loadError}
        metadata={graph && graph.metadata}
        inDetail={!!selectedNode}
        onBack={() => setSelectedId(null)}
      />
      <main className="main">
        {selectedNode ? (
          <DeviceDetail node={selectedNode} />
        ) : (
          <TopologyView graph={graph} onSelect={setSelectedId} />
        )}
      </main>
    </div>
  );
}
