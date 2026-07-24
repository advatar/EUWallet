#!/usr/bin/env bash
set -euo pipefail

entitlements="App/EUWalletDemo.entitlements"
project="EUWalletDemo.xcodeproj/project.pbxproj"
capability="com.apple.developer.identity-document-services.document-provider.mobile-document-types"
extension_plist="DocumentProvider/Info.plist"
extension_point="com.apple.identity-document-services.document-provider-ui"

expected_types=(
  "eu.europa.ec.av.1"
  "org.iso.23220.photoid.1"
  "org.iso.18013.5.1.mDL"
  "eu.europa.ec.eudi.pid.1"
)

for index in "${!expected_types[@]}"; do
  actual="$(/usr/libexec/PlistBuddy \
    -c "Print :${capability}:${index}" "${entitlements}")"
  if [[ "${actual}" != "${expected_types[$index]}" ]]; then
    echo "Identity Document type ${index} is '${actual}', expected '${expected_types[$index]}'" >&2
    exit 1
  fi
done

if /usr/libexec/PlistBuddy \
  -c "Print :${capability}:${#expected_types[@]}" "${entitlements}" >/dev/null 2>&1; then
  echo "Identity Document Provider entitlement contains an unexpected extra type" >&2
  exit 1
fi

grep -q 'CODE_SIGN_ENTITLEMENTS = App/EUWalletDemo.entitlements;' "${project}"
grep -q 'DEVELOPMENT_TEAM = L2AF8KFX35;' "${project}"
actual_extension_point="$(/usr/libexec/PlistBuddy \
  -c 'Print :EXAppExtensionAttributes:EXExtensionPointIdentifier' "${extension_plist}")"
if [[ "${actual_extension_point}" != "${extension_point}" ]]; then
  echo "Identity Document Provider extension point is missing or invalid" >&2
  exit 1
fi
grep -q 'EUWalletDocumentProvider.appex in Embed ExtensionKit Extensions' "${project}"
data_protection="$(/usr/libexec/PlistBuddy \
  -c 'Print :com.apple.developer.default-data-protection' "${entitlements}")"
if [[ "${data_protection}" != "NSFileProtectionComplete" ]]; then
  echo "Complete data protection is missing from the generated entitlement" >&2
  exit 1
fi

echo "Identity Document Provider entitlement, UI extension, and signing source are reproducible."
