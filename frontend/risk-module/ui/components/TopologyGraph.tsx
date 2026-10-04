"use client";

import {useCallback, useMemo, useState} from "react";
import Image from "next/image";
import {useRouter} from "next/navigation";
import {ReactFlow, Background, Controls, getBezierPath, useNodesState, useEdgesState, Handle, Position, type Node, type Edge, type NodeProps, type EdgeProps, ConnectionLineType} from "@xyflow/react";
import dagre from "@dagrejs/dagre";
import {cn} from "@/lib/utils";
import "@xyflow/react/dist/style.css";

/** Edge with theme-aware stroke and arrow */
function BasicEdge({sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition}: EdgeProps) {
	const [path] = getBezierPath({
		sourceX,
		sourceY,
		sourcePosition,
		targetX,
		targetY,
		targetPosition,
	});

	return (
		<g>
			<defs>
				<marker
					id="arrowhead"
					markerWidth="10"
					markerHeight="10"
					refX="9"
					refY="3"
					orient="auto"
				>
					<polygon
						points="0 0, 10 3, 0 6"
						fill="var(--foreground)"
					/>
				</marker>
			</defs>
			<path
				d={path}
				fill="none"
				stroke="var(--foreground)"
				strokeWidth={2}
				markerEnd="url(#arrowhead)"
				strokeLinecap="round"
				strokeLinejoin="round"
			/>
		</g>
	);
}

const edgeTypes = {smoothstep: BasicEdge};

export type TopologyNode = {id: string; label: string};
export type TopologyEdge = {source: string; target: string} | {from: string; to: string};

const NODE_WIDTH = 120;
const NODE_HEIGHT = 120;

type NodeData = {label: string; id: string; risk?: number};

/** Map node id to your PNG icon path in public/icons */
function getIconSrc(id: string): string {
	if (id.startsWith("firewall")) return "/icons/firewall.png";
	if (id.startsWith("core-switch")) return "/icons/coreswitch.png";
	if (id.includes("switch")) return "/icons/switch.png";
	if (id.startsWith("db-srv")) return "/icons/db-srv.png";
	if (id.startsWith("user-pc")) return "/icons/userpc.png";
	if (id.startsWith("web-srv")) return "/icons/web-srv.png";
	if (id.startsWith("app-srv")) return "/icons/app-srv.png";
	return "/icons/web-srv.png";
}

function TopologyNodeComponent({data, selected}: NodeProps<Node<NodeData>>) {
	const iconSrc = getIconSrc(data.id);
	const risk = data.risk ?? 0;
	const riskClasses =
		risk >= 7.5
			? "border-red-400 bg-red-500/10 dark:border-red-500 dark:bg-red-500/20"
			: risk >= 4
			? "border-amber-400 bg-amber-500/10 dark:border-amber-500 dark:bg-amber-500/20"
			: "border-emerald-400 bg-emerald-500/10 dark:border-emerald-500 dark:bg-emerald-500/20";

	return (
		<div className="flex flex-col items-center justify-center gap-2">
			<Handle
				type="target"
				position={Position.Top}
				style={{background: "transparent", border: "none"}}
			/>
			<div
				className={cn(
					"flex justify-center cursor-pointer flex-col items-center gap-1 rounded-xl border-2 px-2 py-2 shadow-md transition-all hover:border-primary hover:bg-accent hover:shadow-lg",
					riskClasses,
					selected && "ring-2 ring-primary ring-offset-2",
				)}
				style={{width: NODE_WIDTH, height: NODE_HEIGHT}}
			>
				<div className="relative size-10 shrink-0 w-full h-full">
					<Image
						src={iconSrc}
						alt={data.label}
						width={100}
						height={100}
						className="object-cover"
						unoptimized
					/>
				</div>
			</div>
			<span className="text-center text-lg font-medium leading-tight text-foreground !text-foreground line-clamp-2" style={{color: 'var(--foreground)'}}>{data.label}</span>
			<Handle
				type="source"
				position={Position.Bottom}
				style={{background: "transparent", border: "none"}}
			/>
		</div>
	);
}

const nodeTypes = {topology: TopologyNodeComponent};

function getLayoutedElements(nodes: TopologyNode[], edges: TopologyEdge[], direction: "TB" | "LR" = "TB", nodeRisk?: Record<string, number>) {
	const g = new dagre.graphlib.Graph().setDefaultEdgeLabel(() => ({}));
	g.setGraph({rankdir: direction, nodesep: 60, ranksep: 80});

	nodes.forEach((node) => {
		g.setNode(node.id, {width: NODE_WIDTH, height: NODE_HEIGHT});
	});

	edges.forEach((e) => {
		const src = "source" in e ? e.source : e.from;
		const tgt = "target" in e ? e.target : e.to;
		g.setEdge(src, tgt);
	});

	dagre.layout(g);

	const isHorizontal = direction === "LR";
	const sourcePos = isHorizontal ? Position.Right : Position.Bottom;
	const targetPos = isHorizontal ? Position.Left : Position.Top;

	const layoutedNodes: Node<NodeData>[] = nodes.map((node, i) => {
		const pos = g.node(node.id) as {x?: number; y?: number} | undefined;
		const x = pos?.x ?? i * (NODE_WIDTH + 20);
		const y = pos?.y ?? 0;
		return {
			id: node.id,
			type: "topology",
			data: {
				label: node.label,
				id: node.id,
				risk: nodeRisk?.[node.id] ?? 0,
			},
			position: {
				x: x - NODE_WIDTH / 2,
				y: y - NODE_HEIGHT / 2,
			},
			sourcePosition: sourcePos,
			targetPosition: targetPos,
		};
	});

	const layoutedEdges: Edge[] = edges.map((e, i) => {
		const src = "source" in e ? e.source : e.from;
		const tgt = "target" in e ? e.target : e.to;
		return {
			id: `e-${src}-${tgt}-${i}`,
			source: src,
			target: tgt,
			type: "smoothstep",
		};
	});

	return {nodes: layoutedNodes, edges: layoutedEdges};
}

interface TopologyGraphProps {
	nodes: TopologyNode[];
	edges: TopologyEdge[];
	nodeRisk?: Record<string, number>;
	onNodeSelect?: (nodeId: string) => void;
	className?: string;
}

export function TopologyGraph({nodes, edges, nodeRisk, onNodeSelect, className}: TopologyGraphProps) {
	const router = useRouter();
	const [lastClickedNode, setLastClickedNode] = useState<string | null>(null);
	const [clickTimeout, setClickTimeout] = useState<NodeJS.Timeout | null>(null);

	const {nodes: layoutedNodes, edges: layoutedEdges} = useMemo(() => {
		if (nodes.length === 0) return {nodes: [], edges: []};
		try {
			return getLayoutedElements(nodes, edges, "TB", nodeRisk);
		} catch {
			return {nodes: [], edges: []};
		}
	}, [nodes, edges, nodeRisk]);

	const [rfNodes, setNodes, onNodesChange] = useNodesState(layoutedNodes);
	const [rfEdges, setEdges, onEdgesChange] = useEdgesState(layoutedEdges);

	const onNodeClick = useCallback(
		(_: React.MouseEvent, node: Node) => {
			if (lastClickedNode === node.id && clickTimeout) {
				// Double click - navigate to asset page
				clearTimeout(clickTimeout);
				setLastClickedNode(null);
				setClickTimeout(null);
				router.push(`/dashboard/asset/${node.id}`);
			} else {
				// Single click - update preview
				if (clickTimeout) {
					clearTimeout(clickTimeout);
				}
				setLastClickedNode(node.id);
				if (onNodeSelect) {
					onNodeSelect(node.id);
				}
				const timeout = setTimeout(() => {
					setLastClickedNode(null);
				}, 300);
				setClickTimeout(timeout);
			}
		},
		[onNodeSelect, router, lastClickedNode, clickTimeout],
	);

	if (nodes.length === 0 || layoutedNodes.length === 0) {
		return <div className={cn("flex min-h-[280px] items-center justify-center rounded-lg border border-dashed bg-muted/20 text-muted-foreground", className)}>{nodes.length === 0 ? "No topology data" : "Unable to layout topology"}</div>;
	}

	return (
		<div className={cn("topology-flow-container h-[450px] w-full min-w-0 rounded-lg border border-border", className, "bg-card")}>
			<ReactFlow
				nodes={rfNodes}
				edges={rfEdges}
				onNodesChange={onNodesChange}
				onEdgesChange={onEdgesChange}
				onNodeClick={onNodeClick}
				nodeTypes={nodeTypes}
				edgeTypes={edgeTypes}
				connectionLineType={ConnectionLineType.SmoothStep}
				defaultEdgeOptions={{type: "smoothstep"}}
				fitView
				fitViewOptions={{padding: 0.25}}
				minZoom={0.4}
				maxZoom={1.5}
				proOptions={{hideAttribution: true}}
				className="rounded-lg"
				style={{width: "100%", height: "100%"}}
			>
				<Background
					gap={20}
					size={1.5}
					color="var(--muted-foreground)"
				/>
				<Controls
					showInteractive={false}
					className="[&>button]:!bg-card [&>button]:!text-foreground [&>button]:!border [&>button]:!border-border [&>button]:hover:!bg-accent [&>button]:hover:!text-accent-foreground"
				/>
			</ReactFlow>
		</div>
	);
}
