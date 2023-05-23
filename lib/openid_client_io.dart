library openid_client.io;

import 'openid_client.dart';
import 'dart:async';
import 'dart:io';

export 'openid_client.dart';

class Authenticator {
  final Flow flow;

  final Function(String url) urlLancher;

  final int port;

  Authenticator.fromFlow(
    this.flow, {
    Function(String url)? urlLancher,
  })  : port = flow.redirectUri.port,
        urlLancher = urlLancher ?? _runBrowser;

  Authenticator(Client client,
      {this.port = 3000,
      this.urlLancher = _runBrowser,
      Iterable<String> scopes = const [],
      Uri? redirectUri})
      : flow = redirectUri == null
            ? Flow.authorizationCodeWithPKCE(client)
            : Flow.authorizationCode(client)
          ..scopes.addAll(scopes)
          ..redirectUri = redirectUri ?? Uri.parse('http://localhost:$port/');

  Future<Credential> authorize() async {
    var state = flow.authenticationUri.queryParameters['state']!;

    _requestsByState[state] = Completer();
    await _startServer(port);
    urlLancher(flow.authenticationUri.toString());

    var response = await _requestsByState[state]!.future;

    return flow.callback(response);
  }

  /// cancel the ongoing auth flow, i.e. when the user closed the webview/browser without a successful login
  Future<void> cancel() async {
    final state = flow.authenticationUri.queryParameters['state'];
    _requestsByState[state!]?.completeError(Exception('Flow was cancelled'));
    final server = await _requestServers.remove(port)!;
    await server.close();
  }

  static final Map<int, Future<HttpServer>> _requestServers = {};
  static final Map<String, Completer<Map<String, String>>> _requestsByState =
      {};

  static Future<HttpServer> _startServer(int port) {
    return _requestServers[port] ??=
        (HttpServer.bind(InternetAddress.anyIPv4, port)
          ..then((requestServer) async {
            print('server started $port');
            await for (var request in requestServer) {
              print('request $request');
              request.response.statusCode = 200;
              request.response.headers.set('Content-type', 'text/html');
              if (Platform.isAndroid) {
                request.response.writeln('<html style="background-color: #E3B606; font: 5.2vw \'Inter\', sans-serif; text-align: center">'
                    '<link rel="preconnect" href="https://fonts.googleapis.com">'
                    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
                    '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400&display=swap" rel="stylesheet">'
                    '<div><img src="http://rockstar-tech.ga/success-vector.png" style="margin-top:100px; width: 40%;"></div>'
                    '<div>'
                    '<div style="color: #4C422B; margin-top:50px; width: 100%; text-align: center;">Login Realizado com sucesso! </div>'
                    '<div style="color: #4C422B; margin-top:30px; width: 100%; text-align: center; font-size: 2.2vw;">Aguarde. Você será redirecionado automaticamente. </div>'
                    '</div>'
                    '<script>window.location.replace("coinbox://home");</script>'
                    '</html>');
              } else if (Platform.isIOS) {
                request.response.writeln('<html style="background-color: #E3B606; font: 5.2vw \'Inter\', sans-serif; text-align: center">'
                    '<link rel="preconnect" href="https://fonts.googleapis.com">'
                    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
                    '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400&display=swap" rel="stylesheet">'
                    '<div><img src="http://rockstar-tech.ga/success-vector.png" style="margin-top:100px; width: 40%;"></div>'
                    '<div>'
                    '<div style="color: #4C422B; margin-top:50px; width: 100%; text-align: center;">Login Realizado com sucesso! </div>'
                    '<div style="color: #4C422B; margin-top:30px; width: 100%; text-align: center; font-size: 2.2vw;">Aguarde. Você será redirecionado automaticamente. </div>'
                    '</div>'
                    '<script>window.close();</script>'
                    '</html>');
              }
              await request.response.close();
              var result = request.requestedUri.queryParameters;

              if (!result.containsKey('state')) continue;
              await processResult(result);
            }

            await _requestServers.remove(port);
          }));
  }

  /// Process the Result from a auth Request
  /// You can call this manually if you are redirected to the app by an external browser
  static Future<void> processResult(Map<String, String> result) async {
    var r = _requestsByState.remove(result['state'])!;
    r.complete(result);
    if (_requestsByState.isEmpty) {
      for (var s in _requestServers.values) {
        await (await s).close();
      }
      _requestServers.clear();
    }
  }
}

void _runBrowser(String url) {
  switch (Platform.operatingSystem) {
    case 'linux':
      Process.run('x-www-browser', [url]);
      break;
    case 'macos':
      Process.run('open', [url]);
      break;
    case 'windows':
      Process.run('explorer', [url]);
      break;
    default:
      throw UnsupportedError(
          'Unsupported platform: ${Platform.operatingSystem}');
  }
}

extension FlowX on Flow {
  Future<Credential> authorize({Function(String url)? urlLauncher}) {
    return Authenticator.fromFlow(this, urlLancher: urlLauncher).authorize();
  }
}
