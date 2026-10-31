import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:securecode/securecode.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late List<MethodCall> calls;
  late MethodChannel channel;
  late SecureCode client;

  setUp(() {
    calls = [];
    client = SecureCode.instance;
    channel = const MethodChannel('securecode/licensing');
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      switch (call.method) {
        case 'init':
          return null;
        case 'machineCode':
          return 'B5LZ-FM37-FXRA-RE5R';
        case 'activate':
          return {
            'ok': true,
            'state': 'valid',
            'message': '',
            'payload': {
              'v': 1,
              'fp': 'B5LZFM37FXRARE5R',
              'pid': '7e9a6cec-c185-45bb-a2fb-d31e96484f7e',
              'iat': 1770000000,
              'exp': 1803542400,
              'cust': 'Test Customer',
              'n': '0011',
              'fl': {'core': true},
              'tol': 1,
              'rb': 3,
            },
          };
        case 'verify':
          return {
            'state': 'valid',
            'message': '',
            'secondsLeft': 31536000,
            'payload': null,
          };
        default:
          return null;
      }
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('initialize forwards the full config map', () async {
    await client.initialize(const ProtectionConfig(
      productId: '7e9a6cec-c185-45bb-a2fb-d31e96484f7e',
      productName: 'MyApp',
      companyName: 'MyCompany',
      devMode: true,
      useKeystoreComponent: true,
    ));
    final call = calls.single;
    expect(call.method, 'init');
    final args = call.arguments as Map<String, Object?>;
    expect(args['productId'], '7e9a6cec-c185-45bb-a2fb-d31e96484f7e');
    expect(args['productName'], 'MyApp');
    expect(args['companyName'], 'MyCompany');
    expect(args['devMode'], true);
    expect(args['useKeystoreComponent'], true);
    expect(args['onDetect'], 'exit');
  });

  test('machineCode returns the native code', () async {
    expect(await client.machineCode(), 'B5LZ-FM37-FXRA-RE5R');
  });

  test('activate maps the native result into typed objects', () async {
    final result = await client.activate('PMRGG-5LTOQ-…');
    expect(result.ok, true);
    expect(result.state, LicenseState.valid);
    expect(result.payload?.customer, 'Test Customer');
    expect(result.payload?.featureFlags['core'], true);
    expect(result.payload?.isLifetime, false);
  });

  test('verify maps unknown states defensively', () async {
    final status = await client.verifyInstalled();
    expect(status.isValid, true);
    expect(status.secondsLeft, 31536000);
  });

  test('LicenseState.fromName falls back to invalid', () {
    expect(LicenseState.fromName('nonsense'), LicenseState.invalid);
    expect(LicenseState.fromName('clockTampered'), LicenseState.clockTampered);
  });
}
