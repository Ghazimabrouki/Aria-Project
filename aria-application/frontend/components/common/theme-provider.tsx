'use client'

import * as React from 'react'

interface ThemeProviderProps {
  children: React.ReactNode
  attribute?: string
  defaultTheme?: string
  enableSystem?: boolean
  disableTransitionOnChange?: boolean
}

interface ThemeContextValue {
  theme: string
  setTheme: (theme: string) => void
  resolvedTheme: string
  themes: string[]
}

const ThemeContext = React.createContext<ThemeContextValue>({
  theme: 'dark',
  setTheme: () => {},
  resolvedTheme: 'dark',
  themes: ['light', 'dark'],
})

export function useTheme() {
  return React.useContext(ThemeContext)
}

function getSystemTheme() {
  if (typeof window === 'undefined') return 'dark'
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export function ThemeProvider({
  children,
  defaultTheme = 'dark',
  enableSystem = true,
  disableTransitionOnChange = false,
}: ThemeProviderProps) {
  const [theme, setThemeState] = React.useState(defaultTheme)
  const [mounted, setMounted] = React.useState(false)

  React.useEffect(() => {
    setMounted(true)
    const saved = localStorage.getItem('aria-theme')
    if (saved) {
      setThemeState(saved)
    } else if (enableSystem) {
      setThemeState('system')
    }
  }, [enableSystem])

  const resolvedTheme = React.useMemo(() => {
    if (theme === 'system' && enableSystem) {
      return getSystemTheme()
    }
    return theme
  }, [theme, enableSystem])

  const setTheme = React.useCallback(
    (newTheme: string) => {
      setThemeState(newTheme)
      try {
        localStorage.setItem('aria-theme', newTheme)
      } catch {
        // ignore
      }
    },
    []
  )

  React.useEffect(() => {
    if (!mounted) return

    const root = document.documentElement
    const isDark = resolvedTheme === 'dark'

    if (disableTransitionOnChange) {
      root.classList.add('transition-none')
      requestAnimationFrame(() => {
        root.classList.remove('transition-none')
      })
    }

    root.classList.remove('light', 'dark')
    root.classList.add(resolvedTheme)
    root.style.colorScheme = resolvedTheme
  }, [resolvedTheme, mounted, disableTransitionOnChange])

  const value = React.useMemo(
    () => ({
      theme,
      setTheme,
      resolvedTheme,
      themes: ['light', 'dark', 'system'] as string[],
    }),
    [theme, setTheme, resolvedTheme]
  )

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  )
}
