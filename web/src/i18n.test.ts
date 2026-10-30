import { initialLocale } from './i18n';

beforeEach(() => localStorage.clear());

test('a first visit uses English even with a non-English browser language', () => {
  vi.spyOn(navigator, 'language', 'get').mockReturnValue('ko-KR');
  expect(initialLocale()).toBe('en');
});

test('an unsupported saved language falls back to English', () => {
  localStorage.setItem('fw.locale', 'unsupported');
  vi.spyOn(navigator, 'language', 'get').mockReturnValue('fr-FR');
  expect(initialLocale()).toBe('en');
});

test('blocked browser storage still allows the English default', () => {
  vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
    throw new DOMException('Storage is blocked', 'SecurityError');
  });
  expect(initialLocale()).toBe('en');
});
