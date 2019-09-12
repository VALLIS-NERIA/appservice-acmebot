using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using ACMESharp.Authorizations;
using ACMESharp.Crypto;
using ACMESharp.Protocol;
using AppService.Acmebot.Internal;
using DnsClient;
using Microsoft.Azure.Management.Dns;
using Microsoft.Azure.Management.Dns.Models;
using Microsoft.Azure.Management.WebSites;
using Microsoft.Azure.Management.WebSites.Models;
using Microsoft.Azure.WebJobs;

namespace AppService.Acmebot
{
    public class AcmeProcess
    {
        public AcmeProcess(IHttpClientFactory httpClientFactory, LookupClient lookupClient, IAcmeProtocolClientFactory acmeProtocolClientFactory,
                           WebSiteManagementClient webSiteManagementClient, DnsManagementClient dnsManagementClient)
        {
            _httpClientFactory = httpClientFactory;
            _lookupClient = lookupClient;
            _acmeProtocolClientFactory = acmeProtocolClientFactory;
            _webSiteManagementClient = webSiteManagementClient;
            _dnsManagementClient = dnsManagementClient;
            AcmeProcess.Instance = this;
        }

        public static AcmeProcess Instance { get; private set; }

        private const string InstanceIdKey = "InstanceId";
        private static readonly string DefaultWebConfigPath = ".well-known/web.config";
        private static readonly string DefaultWebConfig = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<configuration>\r\n  <system.webServer>\r\n    <handlers>\r\n      <clear />\r\n      <add name=\"StaticFile\" path=\"*\" verb=\"*\" modules=\"StaticFileModule\" resourceType=\"Either\" requireAccess=\"Read\" />\r\n    </handlers>\r\n    <staticContent>\r\n      <remove fileExtension=\".\" />\r\n      <mimeMap fileExtension=\".\" mimeType=\"text/plain\" />\r\n    </staticContent>\r\n    <rewrite>\r\n      <rules>\r\n        <clear />\r\n      </rules>\r\n    </rewrite>\r\n  </system.webServer>\r\n  <system.web>\r\n    <authorization>\r\n      <allow users=\"*\"/>\r\n    </authorization>\r\n  </system.web>\r\n</configuration>";

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly LookupClient _lookupClient;
        private readonly IAcmeProtocolClientFactory _acmeProtocolClientFactory;
        private readonly WebSiteManagementClient _webSiteManagementClient;
        private readonly DnsManagementClient _dnsManagementClient;

        public async Task<OrderDetails> Order(IList<string> hostNames)
        {
            var acmeProtocolClient = await _acmeProtocolClientFactory.CreateClientAsync();

            return await acmeProtocolClient.CreateOrderAsync(hostNames);
        }

        public async Task Http01Precondition(Site site)
        {
            var config = await _webSiteManagementClient.WebApps.GetConfigurationAsync(site);

            // 既に .well-known が仮想アプリケーションとして追加されているか確認
            var virtualApplication = config.VirtualApplications.FirstOrDefault(x => x.VirtualPath == "/.well-known");

            if (virtualApplication == null)
            {
                // .well-known を仮想アプリケーションとして追加
                config.VirtualApplications.Add(new VirtualApplication
                {
                    VirtualPath = "/.well-known",
                    PhysicalPath = "site\\.well-known",
                    PreloadEnabled = false
                });
            }
            else
            {
                // 追加済みの場合は物理パスを変更しているので対処
                virtualApplication.PhysicalPath = "site\\.well-known";
            }

            await _webSiteManagementClient.WebApps.UpdateConfigurationAsync(site, config);
        }

        public async Task<ChallengeResult> Http01Authorization(Site site, string authzUrl)
        {
            var acmeProtocolClient = await _acmeProtocolClientFactory.CreateClientAsync();

            var authz = await acmeProtocolClient.GetAuthorizationDetailsAsync(authzUrl);

            // HTTP-01 Challenge の情報を拾う
            var challenge = authz.Challenges.First(x => x.Type == "http-01");

            var challengeValidationDetails = AuthorizationDecoder.ResolveChallengeForHttp01(authz, challenge, acmeProtocolClient.Signer);

            var credentials = await _webSiteManagementClient.WebApps.ListPublishingCredentialsAsync(site);

            // Kudu API を使い、Answer 用のファイルを作成
            var kuduClient = new KuduApiClient(site.ScmSiteUrl(), credentials.PublishingUserName, credentials.PublishingPassword);

            await kuduClient.WriteFileAsync(DefaultWebConfigPath, DefaultWebConfig);
            await kuduClient.WriteFileAsync(challengeValidationDetails.HttpResourcePath, challengeValidationDetails.HttpResourceValue);

            return new ChallengeResult
            {
                Url = challenge.Url,
                HttpResourceUrl = challengeValidationDetails.HttpResourceUrl,
                HttpResourceValue = challengeValidationDetails.HttpResourceValue
            };
        }

        public async Task<bool> CheckHttpChallenge(ChallengeResult challenge)
        {
            // 実際に HTTP でアクセスして確認する
            var insecureHttpClient = _httpClientFactory.CreateClient("InSecure");

            var httpResponse = await insecureHttpClient.GetAsync(challenge.HttpResourceUrl);

            // ファイルにアクセスできない場合はエラー
            if (!httpResponse.IsSuccessStatusCode)
            {
                // リトライする
                return false;
            }

            var fileContent = await httpResponse.Content.ReadAsStringAsync();

            // ファイルに今回のチャレンジが含まれていない場合もエラー
            if (fileContent != challenge.HttpResourceValue)
            {
                throw new InvalidOperationException($"{challenge.HttpResourceValue} value is not correct.");
            }

            return true;
        }

        public async Task Dns01Precondition(IList<string> hostNames)
        {
            // Azure DNS が存在するか確認
            var zones = await _dnsManagementClient.Zones.ListAsync();

            foreach (var hostName in hostNames)
            {
                if (!zones.Any(x => hostName.EndsWith(x.Name)))
                {
                    throw new InvalidOperationException($"Azure DNS zone \"{hostName}\" is not found");
                }
            }
        }

        public async Task<IList<ChallengeResult>> Dns01Authorization(IList<string> authorizations) {
            var acmeProtocolClient = await _acmeProtocolClientFactory.CreateClientAsync();

            var list = new List<(RecordSet, string, string, string, string, string)>();
            var challenges = new List<ChallengeResult>();
            foreach (string authorization in authorizations) {
                var authz = await acmeProtocolClient.GetAuthorizationDetailsAsync(authorization);
                var challenge = authz.Challenges.First(x => x.Type == "dns-01");
                var challengeValidationDetails = AuthorizationDecoder.ResolveChallengeForDns01(authz, challenge, acmeProtocolClient.Signer);
                var zone = (await _dnsManagementClient.Zones.ListAsync()).First(x => challengeValidationDetails.DnsRecordName.EndsWith(x.Name));
                var resourceId = AzureHelper.ParseResourceId(zone.Id);
                var acmeDnsRecordName = challengeValidationDetails.DnsRecordName.Replace("." + zone.Name, "");

                RecordSet recordSet;
                try {
                    recordSet = await this._dnsManagementClient.RecordSets.GetAsync(resourceId.resourceGroup, zone.Name, acmeDnsRecordName, RecordType.TXT);
                    recordSet.TxtRecords.Clear();
                }
                catch {
                    continue;
                }

                list.Add((recordSet, challenge.Url, resourceId.resourceGroup, zone.Name, acmeDnsRecordName, challengeValidationDetails.DnsRecordValue));
            }

            foreach (var input in list) {
                var (recordSet, challengeUrl, resourceGroup, zoneName, recordName, recordValue) = input;

                if (recordSet == null) {
                    recordSet = new RecordSet
                    {
                        TTL = 60,
                        TxtRecords = new[]
                        {
                            new TxtRecord(new[] {recordValue})
                        }
                    };
                }
                else {
                    recordSet.TTL = 60;

                    // 既存の TXT レコードに値を追加する
                    recordSet.TxtRecords.Add(new TxtRecord(new[] { recordValue }));
                }

                await _dnsManagementClient.RecordSets.CreateOrUpdateAsync(resourceGroup, zoneName, recordName, RecordType.TXT, recordSet);

                var result = new ChallengeResult
                {
                    Url = challengeUrl,
                    DnsRecordName = recordName,
                    DnsRecordValue = recordValue
                };
                challenges.Add(result);
            }

            return challenges;
        }

        public async Task<ChallengeResult> Dns01Authorization(string authzUrl, string instanceId)
        {
            var acmeProtocolClient = await _acmeProtocolClientFactory.CreateClientAsync();

            var authz = await acmeProtocolClient.GetAuthorizationDetailsAsync(authzUrl);

            // DNS-01 Challenge の情報を拾う
            var challenge = authz.Challenges.First(x => x.Type == "dns-01");

            var challengeValidationDetails = AuthorizationDecoder.ResolveChallengeForDns01(authz, challenge, acmeProtocolClient.Signer);

            // Azure DNS の TXT レコードを書き換え
            var zone = (await _dnsManagementClient.Zones.ListAsync()).First(x => challengeValidationDetails.DnsRecordName.EndsWith(x.Name));

            var resourceId = AzureHelper.ParseResourceId(zone.Id);

            // Challenge の詳細から Azure DNS 向けにレコード名を作成
            var acmeDnsRecordName = challengeValidationDetails.DnsRecordName.Replace("." + zone.Name, "");

            RecordSet recordSet;

            try
            {
                recordSet = await _dnsManagementClient.RecordSets.GetAsync(resourceId.resourceGroup, zone.Name, acmeDnsRecordName, RecordType.TXT);
            }
            catch
            {
                recordSet = null;
            }

            if (recordSet != null)
            {
                if (recordSet.Metadata == null || !recordSet.Metadata.TryGetValue(InstanceIdKey, out var dnsInstanceId) || dnsInstanceId != instanceId)
                {
                    recordSet.Metadata = new Dictionary<string, string>
                    {
                        {InstanceIdKey, instanceId}
                    };

                    recordSet.TxtRecords.Clear();
                }

                recordSet.TTL = 60;

                // 既存の TXT レコードに値を追加する
                recordSet.TxtRecords.Add(new TxtRecord(new[] {challengeValidationDetails.DnsRecordValue}));
            }
            else
            {
                // 新しく TXT レコードを作成する
                recordSet = new RecordSet
                {
                    TTL = 60,
                    Metadata = new Dictionary<string, string>
                    {
                        {InstanceIdKey, instanceId}
                    },
                    TxtRecords = new[]
                    {
                        new TxtRecord(new[] {challengeValidationDetails.DnsRecordValue})
                    }
                };
            }

            await _dnsManagementClient.RecordSets.CreateOrUpdateAsync(resourceId.resourceGroup, zone.Name, acmeDnsRecordName, RecordType.TXT, recordSet);

            return new ChallengeResult
            {
                Url = challenge.Url,
                DnsRecordName = challengeValidationDetails.DnsRecordName,
                DnsRecordValue = challengeValidationDetails.DnsRecordValue
            };
        }

        public async Task<bool> CheckDnsChallenge(IEnumerable<ChallengeResult> challenge)
        {
            foreach (var challengeResult in challenge)
            {
                if (!await CheckDnsChallenge(challengeResult))
                {
                    return false;
                }
            }

            return true;
        }

        public async Task<bool> CheckDnsChallenge(ChallengeResult challenge)
        {
            // 実際に ACME の TXT レコードを引いて確認する
            var queryResult = await _lookupClient.QueryAsync(challenge.DnsRecordName, QueryType.TXT);

            var txtRecords = queryResult.Answers
                                        .OfType<DnsClient.Protocol.TxtRecord>()
                                        .ToArray();

            // レコードが存在しなかった場合はエラー
            if (txtRecords.Length == 0)
            {
                return false;
            }

            // レコードに今回のチャレンジが含まれていない場合もエラー
            if (!txtRecords.Any(x => x.Text.Contains(challenge.DnsRecordValue)))
            {
                return false;
            }

            return true;
        }

        public async Task CheckIsReady(OrderDetails orderDetails)
        {
            var acmeProtocolClient = await _acmeProtocolClientFactory.CreateClientAsync();

            orderDetails = await acmeProtocolClient.GetOrderDetailsAsync(orderDetails.OrderUrl, orderDetails);

            if (orderDetails.Payload.Status == "pending")
            {
                // pending の場合はリトライする
                throw new RetriableActivityException("ACME domain validation is pending.");
            }

            if (orderDetails.Payload.Status == "invalid")
            {
                // invalid の場合は最初から実行が必要なので失敗させる
                throw new InvalidOperationException("Invalid order status. Required retry at first.");
            }
        }

        public async Task AnswerChallenges(IList<ChallengeResult> challenges)
        {
            var acmeProtocolClient = await _acmeProtocolClientFactory.CreateClientAsync();

            // Answer の準備が出来たことを通知
            foreach (var challenge in challenges)
            {
                await acmeProtocolClient.AnswerChallengeAsync(challenge.Url);
            }
        }

        public async Task<(string, byte[])> FinalizeOrder(IList<string> hostNames, OrderDetails orderDetails)
        {

            // ECC 256bit の証明書に固定
            var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var csr = CryptoHelper.Ec.GenerateCsr(hostNames, ec);

            // Order の最終処理を実行し、証明書を作成
            var acmeProtocolClient = await _acmeProtocolClientFactory.CreateClientAsync();

            var finalize = await acmeProtocolClient.FinalizeOrderAsync(orderDetails.Payload.Finalize, csr);

            var httpClient = _httpClientFactory.CreateClient();

            var certificateData = await httpClient.GetByteArrayAsync(finalize.Payload.Certificate);

            // 秘密鍵を含んだ形で X509Certificate2 を作成
            var (certificate, chainCertificate) = X509Certificate2Helper.LoadFromPem(certificateData);

            var certificateWithPrivateKey = certificate.CopyWithPrivateKey(ec);

            var x509Certificates = new X509Certificate2Collection(new[] {certificateWithPrivateKey, chainCertificate});

            // PFX 形式としてエクスポート
            return (certificateWithPrivateKey.Thumbprint, x509Certificates.Export(X509ContentType.Pfx, "P@ssw0rd"));
        }
    }
}