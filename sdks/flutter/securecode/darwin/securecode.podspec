Pod::Spec.new do |s|
  s.name             = 'securecode'
  s.version          = '1.0.0'
  s.summary          = 'SecureCode — offline, hardware-locked, Ed25519-signed licensing for Flutter (iOS/macOS).'
  s.description      = <<-DESC
  Offline licensing client SDK: serial keys issued by the SecureCode
  protector verify on-device with no network, ever. Hardware-locked,
  time-limited, revocable, with anti-rollback and anti-debug layers.
  DESC
  s.homepage         = 'https://example.com/securecode'
  s.license          = { :type => 'Proprietary' }
  s.author           = { 'SecureCode' => 'support@example.com' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*.{swift,h,m}'
  s.dependency 'Flutter'
  s.platform = { :ios => '13.0', :osx => '10.15' }
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_VERSION' => '5.9',
  }
  s.swift_version = '5.9'

  # NOTE: Classes/SecureCodeKit/** is SYNCED from
  # sdks/apple/SecureCodeKit — never edit it here; run
  #   python sdks/sync_native.py
end
