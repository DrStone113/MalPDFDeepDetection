module.exports = {
      darkMode: "class",
      theme: {
        extend: {
          colors: {
            surface: "#FAF8FF",
            "surface-dim": "#D2D9F4",
            "surface-bright": "#FAF8FF",
            "surface-container-lowest": "#FFFFFF",
            "surface-container-low": "#F2F3FF",
            "surface-container": "#EAEDFF",
            "surface-container-high": "#E2E7FF",
            "surface-container-highest": "#DAE2FD",
            "on-surface": "#131B2E",
            "on-surface-variant": "#414753",
            outline: "#717785",
            "outline-variant": "#C1C6D6",
            primary: {
              DEFAULT: "#0059B5",
              container: "#0071E3",
              fixed: "#D7E2FF",
              "fixed-dim": "#ABC7FF",
            },
            secondary: {
              DEFAULT: "#4C4ACA",
              container: "#6664E4",
              fixed: "#E2DFFF",
              "fixed-dim": "#C2C1FF",
            },
            tertiary: {
              DEFAULT: "#006A26",
              container: "#008633",
              fixed: "#72FE88",
              "fixed-dim": "#53E16F",
            },
            error: {
              DEFAULT: "#BA1A1A",
              container: "#FFDAD6",
              "on-container": "#93000A",
            },
            accent: {
              xai: "#5856D6",
              safe: "#34C759",
              warning: "#FF9500",
              threat: "#FF3B30",
            },
          },
          fontFamily: {
            sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "sans-serif"],
            mono: ["JetBrains Mono", "monospace"],
          },
          borderRadius: {
            "2xl": "1.25rem",
            "3xl": "1.75rem",
            "4xl": "2.25rem",
          },
        },
      },
    };
