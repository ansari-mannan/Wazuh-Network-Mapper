import { AssetDetail } from "@/risk-module/ui/screens/AssetDetail";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function AssetDetailPage({ params }: PageProps) {
  const { id } = await params;
  return <AssetDetail assetId={id} />;
}
