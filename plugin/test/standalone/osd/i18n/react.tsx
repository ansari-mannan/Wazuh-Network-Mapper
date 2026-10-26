// Stand-in for @osd/i18n/react, which only components/app.tsx imports: the
// provider renders its children, as the dashboard's adds no markup of its own.
import React, { ReactNode } from 'react';

export function I18nProvider({ children }: { children?: ReactNode }) {
  return <>{children}</>;
}
