import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = {
  title: "SQLi DETECT · P18",
  description: "SQLi DETECT — laboratoire local, éthique, 0 GPU.",
};
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="fr"><body>{children}</body></html>;
}
