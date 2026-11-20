// Service worker: only for push. Pushes from the relay are empty on
// purpose (no sender, no text), so all it can say is that something arrived.
// Opening the app fetches and decrypts it.

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  event.waitUntil(
    self.registration.showNotification('New message', {
      body: 'Open Messenger to read it.',
      tag: 'messenger',
      renotify: true,
      icon: 'icons/Icon-192.png',
      badge: 'icons/Icon-192.png',
    }),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      if (windows.length) return windows[0].focus();
      return self.clients.openWindow('./');
    })(),
  );
});
