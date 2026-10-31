// SecureCode Flutter demo — the complete customer flow:
//
//   1. "Machine code" shows THIS device's XXXX-XXXX-XXXX-XXXX code.
//   2. The vendor (you) issues a serial for that code in the protector.
//   3. The customer pastes the serial -> Activate.
//   4. Every launch: verifyInstalled() silently checks the license
//      (signature, device binding, expiry, clock, blacklist).
//   5. "Run self-test" validates the wire format on THIS device against
//      the repo's fixed conformance vectors (release smoke test).
//
// devMode keeps the anti-RE layer quiet while developing — NEVER ship it.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:securecode/securecode.dart';

void main() {
  runApp(const SecureCodeDemo());
}

class SecureCodeDemo extends StatefulWidget {
  const SecureCodeDemo({super.key});

  @override
  State<SecureCodeDemo> createState() => _SecureCodeDemoState();
}

class _SecureCodeDemoState extends State<SecureCodeDemo> {
  final _secureCode = SecureCode.instance;
  final _serialController = TextEditingController();

  String _machineCode = '—';
  String _statusText = 'initializing…';
  bool _ready = false;

  @override
  void initState() {
    super.initState();
    _bootstrap();
  }

  Future<void> _bootstrap() async {
    await _secureCode.initialize(const ProtectionConfig(
      productId: '7e9a6cec-c185-45bb-a2fb-d31e96484f7e', // demo product
      productName: 'SecureNotepad',
      companyName: 'SecureCode',
      devMode: true, // keep debuggable while developing; false in release!
    ));
    final code = await _secureCode.machineCode();
    final status = await _secureCode.verifyInstalled();
    setState(() {
      _machineCode = code;
      _statusText = status.isValid
          ? 'Licensed${status.payload?.customer?.isEmpty ?? true ? '' : ' to ${status.payload!.customer}'}'
          : 'Not licensed (${status.state.name})';
      _ready = true;
    });
  }

  Future<void> _activate() async {
    final result = await _secureCode.activate(_serialController.text);
    setState(() {
      _statusText = result.ok
          ? 'Activated${result.payload?.customer?.isEmpty ?? true ? '' : ' — ${result.payload!.customer}'}'
          : 'Activation failed: ${result.message}';
    });
  }

  Future<void> _selfTest() async {
    final vectors = await rootBundle.loadString('assets/vectors.json');
    final report = await _secureCode.runSelfTest(vectors);
    setState(() {
      _statusText = report.allOk
          ? 'Self-test passed (${report.entries.length} vectors)'
          : 'Self-test FAILED — see console';
      if (!report.allOk) {
        report.entries.where((e) => !e.ok).forEach(debugPrint);
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('SecureCode demo')),
        body: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              SelectableText('Machine code:\n$_machineCode',
                  style: const TextStyle(fontSize: 16)),
              const SizedBox(height: 24),
              TextField(
                controller: _serialController,
                maxLines: 3,
                decoration: const InputDecoration(
                    labelText: 'Serial key (from the protector)'),
              ),
              const SizedBox(height: 12),
              FilledButton(
                onPressed: _ready ? _activate : null,
                child: const Text('Activate'),
              ),
              const SizedBox(height: 12),
              OutlinedButton(
                onPressed: _ready ? _selfTest : null,
                child: const Text('Run self-test (conformance vectors)'),
              ),
              const SizedBox(height: 24),
              Text(_statusText),
            ],
          ),
        ),
      ),
    );
  }
}
