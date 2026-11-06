import catalogs from './authority-locales.json';
import { locales } from './i18n';
import { authoritySigningReasons } from './signing-readiness';

test('all eight authority catalogues have complete nonempty messages with matching interpolation fields', () => {
  expect(Object.keys(catalogs).sort()).toEqual([...locales].sort());
  const keys = Object.keys(catalogs.en).sort();
  for (const locale of locales) {
    expect(Object.keys(catalogs[locale]).sort()).toEqual(keys);
    for (const key of keys) {
      const value = catalogs[locale][key as keyof typeof catalogs.en];
      expect(value.trim()).not.toBe('');
      expect(value.match(/\{\w+\}/g) ?? []).toEqual(catalogs.en[key as keyof typeof catalogs.en].match(/\{\w+\}/g) ?? []);
    }
  }
});

test('every canonical v3 authority blocker has a message in all eight locales', () => {
  for (const locale of locales) {
    for (const reason of authoritySigningReasons) {
      const key = `signing.reason.${reason}` as keyof typeof catalogs.en;
      expect(catalogs[locale][key]?.trim()).toBeTruthy();
    }
  }
});
