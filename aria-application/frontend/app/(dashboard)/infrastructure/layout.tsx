import { Metadata } from "next";

export const metadata: Metadata = {
  title: "Infrastructure — ARIA",
  description: "Infrastructure resource anomaly investigations",
};

export default function InfrastructureLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col h-full">
      {children}
    </div>
  );
}
