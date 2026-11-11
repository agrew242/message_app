{{flutter_js}}
{{flutter_build_config}}

// The encryption core and its web glue load alongside the app; the app
// waits for this before doing anything.
window.messengerLoading = import('./messenger/messenger_web.js').catch((e) => {
  console.error(e);
  window.messengerLoadError = String(e);
});

_flutter.loader.load({
  // Serve the renderer from this site, not a CDN.
  config: { canvasKitBaseUrl: 'canvaskit/' },
  onEntrypointLoaded: async (engineInitializer) => {
    const appRunner = await engineInitializer.initializeEngine();
    document.getElementById('loading')?.remove();
    await appRunner.runApp();
  },
});
