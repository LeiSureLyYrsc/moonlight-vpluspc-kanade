// 不带版本号的 import 取当前 Qt 的最新 API（和 main.qml 一致）。
// 写成 import QtQuick 2.9 会把 CI（Qt 6.12）里较新的属性挡在门外，
// 运行期直接加载失败（#153 同类问题）。
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window

import Kanade 1.0
import SdlGamepadKeyNavigation 1.0

import "settings"
import "theme"

// Kanade 在线设备页：登录服务、用两种方式添加设备、管理已有授权。
//
// 边界（和计划 §2 一致）：
// - 在线会话从设备行显式启动；数据路径 ready 只在会话启动后由侧车报告。
//   「连接」入口与 native pairing/app/stream 动作分别按各自真实条件门控。
// - 「已添加授权」「连接状态」「Sunshine 原生配对」是三件独立的事，
//   分行显示；原生配对云端观测不到，恒为「未知」。
// - 授权被移除、会话被关闭或租约到期时只停在这里，绝不自动回落到
//   局域网地址；这条写进文案，不只写在代码注释里。
// - 错误只按 errorCode 白名单映射成固定文案，不回显响应体，也不替
//   pair_unavailable 这类模糊错误推断原因。
// - 密码和设备码用本文件的 SecretField：掩码常开（passwordMaskDelay 0）、
//   带 ImhHiddenText/ImhSensitiveData，并且不挂屏幕键盘。
//   GamepadKeyboard.qml 会把 field.text 抄进一个不掩码的缓冲框
//   （GamepadKeyboard.qml:30–32 → 104），密码进那条路等于明文上屏，
//   所以密码框一律不给它开口子，也不改全局键盘本身。
// - 服务端给的字符串一律按纯文本画（见 asPlainText）。
// - 密码只在输入框里以掩码存在，提交后立刻清空；页面失活时也清空。
//   不打印、不持久化、不进任何日志。
// - 原生 LAN 流程（PcView / AppView / addNewHostManually）完全不走这里。
//
// ---- REM-2：四种状态分开显示 ----
//
// 在线模式有四个必须各自独立的状态。页面永远分行显示，绝不合并成一句
// 「可以连接了」：
//   1. 授权（grant）：主机把这一安装加进了 Kanade。来源 GET /v1/devices。
//   2. Kanade 会话：控制面的 offer / 租约 / 双端激活。来源控制器自己的
//      onlineState / activationConfirmed / leaseValid。
//   3. Sunshine 原生配对：设备码与原生证书这一层。Kanade 恒返回 unknown。
//   4. 在线数据路径：本机固定端口组与命名管道是否通了。只有 onlineReady 一个来源。
//
// 名称很重要：onlineReady 只代表「固定数据路径通了」。它既不代表已完成
// Sunshine 原生配对，也不代表已选中应用，更不代表正在出画面。所以界面上
// 这一栏叫「数据路径 / Online data path」，不叫「串流」；就绪时文案指向
// 下一步（完成配对或选择应用），而不是笼统的「可以连接了」。
//
// 同理，onlineSupported == false 不只表示「这个构建没编进去」——它也可能是
// 本机没有运行时配置或尚未完成认证。文案因此写「此安装尚未配置」，
// 不写「此版本不可用」。
//
// 控制器接口（本页只用这些名字）：
//   onlineSupported / onlineState / onlineStopReason / onlineErrorCode /
//   onlineSessionId / activationConfirmed / onlineReady / leaseValid /
//   leaseRemainingMs，
//   canStartOnlineSessionForGrant(grantId, hostId) /
//   startOnlineSessionForGrant(grantId, hostId) / cancelOnlineSession() /
//   clearOnlineError() / disableCredentialDumps()。
//
// 对端身份（主机安装 ID / key version / 公钥）由本机运行时配置提供，
// 不在 GET /v1/devices 里，也不经过 QML。本页只传 grantId 与 hostId，
// 控制器按运行时配置精确核对这一行，所以界面不可能把身份绑到别的机器上。
//
// 关键区分：activationConfirmed 与 leaseValid 都只是控制面事实；
// onlineState === "active" 只说明「服务端认这条会话」。唯一能说明数据面
// 可用的是 onlineReady，而它只由侧车的 ready 事件驱动。本页不把控制面状态
// 画成「已连接 / 可串流」。
//
// PIN：在线路径不接受任何 PIN 输入（本文件没有 PIN 输入框）。原生配对的
// 首个 PIN 仍由 Moonlight 本地生成，并以既有配对弹窗（PcView 的 pairDialog
// 模式）短暂显示，由人在 Foundation 面板提交；PIN 不进日志、参数、环境变量，
// 也不交给 Kanade。
FocusScope {
    id: page

    objectName: qsTr("Online devices")

    readonly property bool supported: KanadeController.supported
    readonly property bool authenticated: KanadeController.authenticated
    readonly property string errorText: errorMessageFor(KanadeController.errorCode)

    // 等待主机批准的请求：只由控制器状态决定，不看 busy ——
    // 请求在飞的时候也必须能取消。
    readonly property bool requestPending: KanadeController.pairState === "pending"

    // 「登录请求在飞」：未登录 + 控制器忙。
    // 其余操作（刷新、添加、移除）都要求已登录，所以这个组合只会是登录，
    // 不会在退出收尾或别处冒出一颗真的能按的「取消登录」。
    readonly property bool loginInFlight: KanadeController.busy && !page.authenticated

    // 添加方式："password" = 设备码 + 添加密码，"confirm" = 请主机批准（需要设备码）
    property string addMethod: "password"

    // ---- 状态文案白名单 ----

    function errorMessageFor(code) {
        switch (code) {
        case "":
            return ""
        case "invalid_credentials":
            return qsTr("Incorrect login or password.")
        case "too_many_attempts":
            return qsTr("Too many attempts. Wait a moment and try again.")
        case "rate_limited":
            return qsTr("Too many requests. Wait a moment and try again.")
        case "user_disabled":
            return qsTr("This account has been disabled.")
        case "insecure_origin":
            return qsTr("This service requires a secure HTTPS address.")
        case "origin_mismatch":
            return qsTr("The service address did not match. Check it and try again.")
        // pair_unavailable 故意保持模糊：不推断是密码错、码不存在还是主机离线。
        case "pair_unavailable":
            return qsTr("This device cannot be added right now. Try again later.")
        case "network_error":
            return qsTr("The service could not be reached. Check the address and your connection.")
        case "tls_error":
            return qsTr("The service's security certificate could not be verified.")
        case "unauthorized":
        case "session_expired":
            return qsTr("Your session has expired. Sign in again.")
        case "not_found":
            return qsTr("This item no longer exists on the service.")
        case "conflict":
            return qsTr("The service rejected the change because it conflicts with the current state.")
        // 用户自己取消的操作不该报错。
        case "cancelled":
            return ""
        case "forbidden":
            return qsTr("The service refused this action.")
        case "invalid_request":
            return qsTr("The service rejected this request. Check the entries and try again.")
        case "protocol_error":
            return qsTr("The service sent an unexpected response. Try again later.")
        case "server_error":
            return qsTr("The service reported an error. Try again later.")
        case "identity_storage_failed":
            return qsTr("This PC could not store its installation identity safely, so online mode cannot continue.")
        default:
            return qsTr("The operation could not be completed. Try again later.")
        }
    }

    function pairStateText(state) {
        switch (state) {
        case "pending":
            return qsTr("Waiting for the host to approve this request…")
        case "approved":
            return qsTr("The host approved this request.")
        case "denied":
            return qsTr("The host declined this request.")
        case "expired":
            return qsTr("The request expired before the host answered.")
        case "cancelled":
            return qsTr("The request was cancelled.")
        default:
            // 未知状态不编造文案
            return ""
        }
    }

    // connectionState 只说明 Kanade 侧会话状态。即使是 active 也只代表
    // 「服务端还认这次会话」，数据面没接通前一律不说「可连接」。
    // 状态集合与 Kanade persistence/sessions.py 的 _connection_state 一致：
    // active / offered / idle。
    function connectionStateText(state) {
        switch (state) {
        case "offered":
            // 会话已申请、主机还没接单。和「添加设备等批准」不是一回事，
            // 所以文案不借用 pairing 的字眼。
            return qsTr("Waiting for the host to accept")
        case "active":
            return qsTr("Online session active")
        case "inactive":
        case "idle":
            return qsTr("Not connected")
        default:
            return qsTr("Unknown")
        }
    }

    // 原生配对（设备码 / 证书）与上面的授权、会话互不影响。
    //
    // Kanade 自己的契约恒返回 unknown（它看不见 Sunshine 的证书信任），
    // 所以 modelData.nativePairing 今天只可能是 unknown。下面多认得三个
    // 取值（unpaired / paired / mismatch），是为了将来原生流程真的报来
    // 结果时不必改这一页；在它落地之前，任何非 unknown 的输入都不会从
    // 这个页面产生 —— 不把「已授权」画成「已配对」，也不把「已配对」
    // 画成「可串流」。
    function nativePairingText(state) {
        switch (state) {
        case "unpaired":
            return qsTr("Not paired")
        case "paired":
            return qsTr("Paired")
        case "mismatch":
            // 证书变了或被钉扎拒绝：必须重新配对，不自动接受新证书。
            return qsTr("Certificate changed — pairing required")
        case "unknown":
            return qsTr("Unknown")
        default:
            return qsTr("Unknown")
        }
    }

    // ---- 在线会话状态（硬引用已定接口）----
    //
    // 这七个属性由控制器方按已定契约提供。这里必须**硬引用**，不能用
    // KanadeController["onlineState"] 这种字符串下标：字符串访问不会建立
    // QML 的绑定依赖，值只会在首次求值时读一次，之后 onlineState 变了
    // 界面也不会更新 —— 那会变成一张写死「没有在线会话」的假卡片。
    //
    // 代价是：在控制器方落地这些属性之前，加载本页会在控制台留下
    // 「属性未定义」的警告，卡片显示为空。这是可接受的过渡态，也远好于
    // 一张静默不更新的卡片；控制器落地后无需改这一页。
    readonly property string onlineState: KanadeController.onlineState
    readonly property string onlineStopReason: KanadeController.onlineStopReason
    readonly property string onlineErrorText:
        page.onlineErrorMessageFor(KanadeController.onlineErrorCode)
    readonly property bool onlineLeaseValid: KanadeController.leaseValid
    readonly property bool onlineActivationConfirmed: KanadeController.activationConfirmed

    // 本构建是否真的带在线会话运行时。onlineSupported 是控制器自己给出的
    // 编译期开关；不支持时整张会话卡都不画，也不留空按钮。
    readonly property bool onlineRuntimeAvailable: KanadeController.onlineSupported

    // 取消只在会话真的在跑时出现。cancelOnlineSession 是 Q_INVOKABLE 方法，
    // 不是属性 —— 方法不建立绑定依赖，但它只影响「可不可点」，不影响
    // 状态文字，所以这里用存在性探测是安全的（状态本身仍走硬引用）。
    readonly property bool canCancelOnline:
        page.onlineRuntimeAvailable &&
        page.controllerHas("cancelOnlineSession") &&
        (page.onlineState === "creating" || page.onlineState === "offering" ||
         page.onlineState === "activating" || page.onlineState === "awaiting_peer" ||
         page.onlineState === "active")

    // Q_INVOKABLE 方法的存在性探测。只用于「这颗按钮该不该出现 / 该不该可点」，
    // 不用于读取会变化的状态值（那必须硬引用，见上）。typeof 对继承链上的
    // 缺失成员返回 "undefined" 而不是抛错，所以这条探测本身是安全的。
    function controllerHas(name) {
        try {
            return typeof KanadeController[name] !== "undefined"
        }
        catch (e) {
            return false
        }
    }

    // Read the notifying Q_PROPERTY directly so Connect re-evaluates when the
    // device snapshot changes. The controller independently validates the row
    // against its pinned runtime before exposing eligibility or starting.
    function deviceSnapshotContains(grantId, hostId) {
        var rows = KanadeController.devices
        for (var i = 0; i < rows.length; ++i) {
            if (rows[i].grantId === grantId && rows[i].hostId === hostId)
                return true
        }
        return false
    }

    // 会话状态文案。全部只描述控制面进展，没有一个词暗示「已连接 / 可串流」。
    function onlineStateText(state) {
        switch (state) {
        case "":
            return ""
        case "idle":
            return qsTr("No online session")
        case "creating":
            return qsTr("Requesting an online session…")
        case "offering":
            return qsTr("Waiting for the host to accept…")
        case "activating":
            return qsTr("Confirming both ends…")
        case "awaiting_peer":
            return qsTr("Waiting for the host to finish confirming…")
        case "active":
            // 只说明控制面状态；数据路径与原生配对分别显示。
            return qsTr("Online session active")
        case "closing":
            return qsTr("Ending the online session…")
        case "closed":
            return qsTr("Online session ended")
        case "failed":
            return qsTr("Online session could not be established")
        default:
            // 未知状态不编造文案
            return qsTr("Unknown")
        }
    }

    // 结束原因白名单。只认得控制器实际给出的拼写；认不出就什么都不显示，
    // 免得把内部枚举名直接摆到界面上。
    function onlineStopReasonText(reason) {
        switch (reason) {
        case "user_cancelled":
            return qsTr("You ended the online session.")
        case "logout":
            return qsTr("Signing out ended the online session.")
        case "server_closed":
            return qsTr("The host or the service ended the online session.")
        case "grant_revoked":
            return qsTr("The authorization was removed, so the online session ended.")
        case "lease_expired":
            return qsTr("The lease ran out, so the online session stopped.")
        case "offer_expired":
            return qsTr("The host did not accept the session in time.")
        case "session_expired":
            return qsTr("The online session expired.")
        case "protocol_error":
            return qsTr("The service sent an unexpected response, so the session was stopped.")
        default:
            return ""
        }
    }

    // 会话错误码白名单。先按会话自己的语义解释，再退回控制面共用的那张表
    // （那张表的兜底文案是通用措辞，不会泄露响应体）。
    function onlineErrorMessageFor(code) {
        switch (code) {
        case "":
            return ""
        case "grant_revoked":
            return qsTr("The authorization for this device was removed, so the online session ended.")
        case "grant_not_found":
            return qsTr("This authorization no longer exists.")
        case "grant_not_bound_to_installation":
            return qsTr("This authorization belongs to a different installation.")
        case "session_closed":
            return qsTr("The online session was closed.")
        case "session_not_found":
            return qsTr("This online session no longer exists.")
        case "session_expired":
            return qsTr("The online session expired.")
        case "session_already_open":
            return qsTr("This device already has an online session open.")
        case "session_already_accepted":
            return qsTr("The host had already accepted this session.")
        case "lease_expired":
            return qsTr("The online session's lease ran out, so it was stopped.")
        case "offer_expired":
            return qsTr("The host did not accept the session in time.")
        case "ticket_invalid":
            return qsTr("The service rejected the session credential.")
        case "channel_binding_invalid":
            return qsTr("The two ends could not prove they share the same secure connection.")
        case "activation_proof_invalid":
            return qsTr("The service rejected the session activation proof.")
        case "activation_conflict":
            return qsTr("Another activation already claimed this session.")
        case "activation_mismatch":
            return qsTr("The two ends did not describe the same session.")
        case "not_session_participant":
            return qsTr("This installation is not part of that session.")
        case "host_disabled":
            return qsTr("This host is disabled.")
        case "host_missing":
            return qsTr("This host no longer exists.")
        case "client_installation_revoked":
        case "host_installation_revoked":
            return qsTr("This installation was revoked on the service. Sign in again.")
        default:
            return page.errorMessageFor(code)
        }
    }

    // ---- 托管数据路径接缝 ----
    //
    // 控制面状态（onlineState / activationConfirmed / leaseValid）都不是
    // 「路径已就绪」。唯一能说明固定端口组已整组绑定、命名管道可用的是控制器
    // 自己的 onlineReady —— 它由侧车的 ready 事件驱动，不是从会话状态推的。
    // 这里直接硬引用它：字符串下标不会建立绑定依赖，界面就不会跟着变。
    //
    // 语义边界（重要）：onlineReady 只表示「本机到主机的固定数据路径通了」。
    // 它不表示已经和 Sunshine 完成原生配对，也不表示已经选中应用，
    // 更不表示正在出画面。所以这一栏叫「数据路径」，不叫「串流」。
    readonly property bool runtimePathReady: KanadeController.onlineReady

    // 注意：这里没有 runtimeStreaming。控制器不提供「正在出画面」这个状态，
    // 本页也不会替它编一个 —— 真实起流后由 StreamSegue 盖在本页上，
    // 那时本页已经不在前台，再去维护一个「Streaming」标签只会变成假状态。
    //
    // 三种诚实状态：本机没有配置 → 已配置但路径没通 → 路径通了。
    function dataPathStateText() {
        if (!page.onlineRuntimeAvailable)
            return qsTr("Not configured for this installation")
        if (page.runtimePathReady)
            // 路径通了只是先决条件：接下来还要完成原生配对或挑一个应用。
            // 所以这里指向下一步，而不是笼统说「可以连接了」。
            return qsTr("Path ready — finish Sunshine pairing or select an app")
        return qsTr("Path not ready")
    }

    // ---- 原生配对与原应用（真正会碰宿主的一段）----
    //
    // 这组属性和方法由产品控制器 KanadeController 提供；底层
    // ManagedNativeController 保持私有、非 QObject，QML 永远看不到它。
    // 全部硬引用（字符串下标不建绑定依赖，界面就不会跟着变）。
    //
    // nativePairingState 九个值，逐一映射；认不出的状态不编造文案。
    // nativeBusy 只表示「正在进行某个原生动作」，不是可用性。
    readonly property string nativeState: KanadeController.nativePairingState
    readonly property bool nativeBusy: KanadeController.nativeBusy
    readonly property string nativePinText: KanadeController.nativePin
    readonly property var nativeApps: KanadeController.nativeApps

    // 原生这一段只有四种可用窗口：
    //   unavailable 本机没有可用原生路径（未就绪 / fixture）
    //   idle        可以开始配对
    //   paired      证书已就位，可以拉应用列表
    //   appsReady   应用列表在手上，可以起流
    //
    // 配对失败后重试「配对」还是「拉列表」，取决于本次运行里证书到底有没有
    // 拿到。QML 看不到证书本身，所以只依据**观测到的真实状态**判断：
    // 曾经到过 paired / loadingApps / appsReady，就说明证书已就位。
    property bool nativeCertificateObserved: false

    onNativeStateChanged: {
        if (page.nativeState === "paired" || page.nativeState === "loadingApps" ||
                page.nativeState === "appsReady") {
            page.nativeCertificateObserved = true
        }
        else if (page.nativeState === "idle" || page.nativeState === "unavailable" ||
                 page.nativeState === "stopped") {
            // 这些状态意味着本次运行已经收尾，证书不再属于当前这一轮。
            page.nativeCertificateObserved = false
        }
    }

    readonly property bool nativeCanPair:
        !page.nativeBusy &&
        (page.nativeState === "idle" || page.nativeState === "pinRejected" ||
         (page.nativeState === "failed" && !page.nativeCertificateObserved))
    readonly property bool nativeCanLoadApps:
        !page.nativeBusy &&
        (page.nativeState === "paired" || page.nativeState === "appsReady" ||
         (page.nativeState === "failed" && page.nativeCertificateObserved))
    readonly property bool nativeCanStream:
        page.nativeState === "appsReady" && !page.nativeBusy &&
        page.nativeApps !== undefined && page.nativeApps.length > 0

    // PIN：由 C++ 为本次配对生成，QML 只做瞬态显示。
    // 本页没有 PIN 输入框，也不接受任何手输 PIN。
    readonly property bool nativePinVisible:
        page.nativeState === "pairing" && page.nativePinText !== ""

    function nativeStateText(state) {
        switch (state) {
        case "":
        case "unavailable":
            return qsTr("Not available")
        case "idle":
            return qsTr("Ready to pair")
        case "pairing":
            return qsTr("Pairing with the host…")
        case "pinRejected":
            return qsTr("The host rejected the PIN")
        case "paired":
            return qsTr("Paired — load the app list")
        case "loadingApps":
            return qsTr("Loading apps…")
        case "appsReady":
            return qsTr("Apps loaded")
        case "failed":
            return qsTr("Pairing or loading failed")
        case "stopped":
            return qsTr("Stopped")
        default:
            return qsTr("Unknown")
        }
    }

    // 原生错误码白名单。nativeErrorCode 是控制器给出的稳定非秘密串，
    // 这里只把认识的翻成人话，认不出就退回通用句。
    function nativeErrorText(code) {
        switch (code) {
        case "":
            return ""
        case "unsupported":
            return qsTr("This build has no native online path.")
        case "not_ready":
            return qsTr("The online data path is not ready yet.")
        case "host_version_unpinned":
            return qsTr("The host application version is not pinned in this installation's configuration.")
        case "pin_wrong":
            return qsTr("The PIN was rejected. Try pairing again.")
        case "pair_failed":
            return qsTr("Native pairing did not complete.")
        case "not_paired":
            return qsTr("Pair with the host before loading apps.")
        case "applist_failed":
            return qsTr("The host did not return its app list.")
        case "lease_expired":
            return qsTr("The online lease ran out, so native actions stopped.")
        case "presend_hook_unavailable":
            return qsTr("This build cannot open a managed stream.")
        default:
            return qsTr("The native action could not be completed.")
        }
    }

    readonly property string nativeErrorDisplay:
        page.nativeErrorText(KanadeController.nativeErrorCode)

    // 起流是同步的「取会话 → push 加载页」。push 之后本页被盖住，但在这
    // 之前 nativePairingState 仍是 appsReady —— 连点两次会向宿主发两次启动。
    // 所以这里用本页自己的标记把窗口关掉，成功 push 或失败都会立刻复位
    // （失败要允许重试，成功时本页已经不在前台）。
    property bool nativeStreamRequested: false

    // 起流入口。只有工厂真的返回了非 null 的 Session 才创建 StreamSegue ——
    // 返回 null 时什么都不 push，只把原因留在 nativeErrorCode 上。
    //
    // 顺序刻意是「先备好组件，再要会话」：createNativeStream 返回的是
    // 裸指针（没有 parent），一旦后面 createObject 失败，那个很重的 Session
    // 就没有归属了。先把组件校验到 Ready，窗口就只剩 createObject 本身失败
    // 这一种情况。
    //
    // 真的走到那一步时怎么办：QML 这边**不能**假定所有权。C++ 侧返回的是
    // 一个没有 parent 的裸指针，ownership 在注释里写的是「交给 caller」，
    // 但 Session 内部还有渲染线程、SDL 与解码器，跨线程 delete 会崩。所以
    // 这里只做确定安全的两件事：不 push、把标记复位、记一条固定错误。
    // 对象由 C++ 侧负责（控制器持有 native 运行，页面移除时会取消会话，
    // 该运行代际作废）。**不调用 session.destroy()**：那不是 JS 创建的对象，
    // 归 JS 回收是错的；若将来 C++ 侧补了显式丢弃接口，再由那一侧改成调用它。
    //
    // 这是唯一一处把 Session* 交给 StreamSegue 的地方，用的是 AppView.qml:684
    // 同一套 createObject + push 写法；所有权随 Session 交给 segue
    // （segue 在 readyForDeletion 里自己置 null 并 gc）。
    function startNativeStream(appId, appName) {
        if (appId === "" || !page.nativeCanStream) {
            return false
        }
        if (page.nativeStreamRequested) {
            return false
        }
        var component = Qt.createComponent("StreamSegue.qml")
        if (component.status !== Component.Ready) {
            console.error("KanadeDevices: StreamSegue.qml unavailable")
            return false
        }
        var session = KanadeController.createNativeStream(appId)
        if (session === null || session === undefined) {
            // 工厂没给真实会话：不建界面、不留半张加载页。
            return false
        }
        page.nativeStreamRequested = true
        var segue = component.createObject(stackView, {
                                               "appName": appName,
                                               "session": session,
                                               "isResume": false
                                           })
        if (segue === null) {
            // 允许重试：会话已建但页面没建成，至少不让标记卡住后续操作。
            KanadeController.discardUnstartedNativeStream(session)
            page.nativeStreamRequested = false
            console.error("KanadeDevices: could not create the stream page")
            return false
        }
        stackView.push(segue)
        return true
    }

    // 页头那张卡里的一句完整说明。单独成句，而不是把两句拼起来 ——
    // 拼接会让译文语序无处可放，也会让翻译记忆存下伪句子。
    function headerDataPathText() {
        if (!page.onlineRuntimeAvailable)
            return qsTr("The online path is not configured for this installation. Devices on your local network work as before.")
        if (page.runtimePathReady)
            // 「配对或选应用」是自配对起的必经步骤，这里必须一起说出来。
            return qsTr("The online path is ready. Finish Sunshine pairing or select an app on the host to start.")
        return qsTr("The online path is not ready. The local network list is a separate way to connect.")
    }

    // ---- 操作 ----

    function submitLogin() {
        if (KanadeController.busy) {
            return
        }

        var url = urlField.text.trim()
        var user = loginField.text
        var secret = passwordField.text
        if (url === "" || user === "" || secret === "") {
            return
        }
        if (!/^https:\/\/.+/i.test(url)) {
            urlError.visible = true
            return
        }
        urlError.visible = false

        // 换服务地址：先明确退出当前 origin，再登录新地址。
        // 不带着旧 origin 的会话去撞新服务。
        if (KanadeController.authenticated && KanadeController.origin !== "" &&
                KanadeController.origin !== url) {
            KanadeController.logout()
        }

        // 密码只作为参数交给控制器，提交后立刻从输入框清掉 ——
        // 无论成功失败，界面上都不留残留。
        passwordField.text = ""
        KanadeController.login(url, user, secret)
    }

    // 登录还没回来时的退路：退出既取消这次登录，也清掉内存凭据和密码框。
    // 控制器把迟到回调按代际丢弃，所以这里不需要额外的「取消」标记。
    function cancelLogin() {
        passwordField.text = ""
        KanadeController.logout()
    }

    function submitAddDevice() {
        if (KanadeController.busy || page.requestPending) {
            return
        }

        var code = codeField.text.trim()
        var secret = addPasswordField.text
        if (code === "") {
            return
        }
        if (page.addMethod === "password" && secret === "") {
            return
        }

        addPasswordField.text = ""
        codeField.text = ""
        KanadeController.addDevice(code, page.addMethod,
                                   page.addMethod === "password" ? secret : "")
    }

    function clearSecrets() {
        passwordField.text = ""
        addPasswordField.text = ""
        codeField.text = ""
    }

    // 服务端给的字符串一律当纯文本。
    //
    // 页面自己的 Text 都写了 textFormat: Text.PlainText；但两处宿主是共享
    // 组件 —— SettingsCard 的副标题和 NavigableMessageDialog 的正文 —— 它们的
    // Text 没写 textFormat，默认 AutoText 会把 '<b>…</b>' 当标记解析。这两处
    // 都要拼外部字符串（服务地址、主机名），所以先按 HTML 转义再拼：即便走
    // 富文本路径，也只会画出字面的尖括号，不会解析标签，更不会去加载
    // <img src=…> 之类的外部资源。
    function asPlainText(value) {
        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
    }

    function focusFirstControl() {
        if (!supported) {
            return
        }
        if (authenticated) {
            // 刷新在飞时它会被禁用，禁用的控件拿不到焦点 —— 退到永远可用的
            // 「退出登录」，别把焦点丢在看不见的壳上。
            if (refreshButton.enabled) {
                refreshButton.forceActiveFocus(Qt.TabFocusReason)
            }
            else if (signOutButton.enabled) {
                signOutButton.forceActiveFocus(Qt.TabFocusReason)
            }
        }
        else {
            urlField.forceActiveFocus(Qt.TabFocusReason)
        }
    }

    // ---- 崩溃转储抑制（安全门，无视觉变化）----
    //
    // 本机的崩溃处理器会把进程内存写进转储，而内存里在提交前就有密码框的
    // 明文。在线页一旦渲染凭据输入，就必须先把这条路径关掉：
    //   * 只在本页真的可见时调用，不因为应用启动而影响纯局域网会话；
    //   * 调用本身没有界面表现，也不改任何控件状态；
    //   * 重复调用必须是无害的（控制器按会话幂等，见方法名 disable*）。
    //
    // Component.onCompleted 覆盖「首次进入本页」；onVisibleChanged 覆盖
    // 页面被缓存后又重新显示的情况。两处走同一个函数，用
    // typeof 检查兜住「控制器尚未落地该方法」的构建 —— 未定义的属性在
    // QML 里读到 undefined，直接调用则会抛 TypeError，这里不允许页面
    // 因为一个尚未接线的安全钩子而加载失败。
    //
    // 注意：这个门只跟进「可见」这一件事，与 onlineState 无关。页面隐藏
    // （例如 StreamSegue 覆盖）时不去撤销任何会话状态。
    function ensureCredentialDumpSuppression() {
        if (!page.visible) {
            return
        }
        if (typeof KanadeController.disableCredentialDumps === "function") {
            KanadeController.disableCredentialDumps()
        }
    }

    Component.onCompleted: page.ensureCredentialDumpSuppression()
    onVisibleChanged: {
        page.ensureCredentialDumpSuppression()
        // 从加载页返回本页时，起流标记必须复位；否则同一页里第二次起流
        // 会被上一次成功留下的标记挡住。成功路径不会走到这里（那时本页
        // 已被盖住），返回时复位正是我们要的语义。
        if (page.visible) {
            page.nativeStreamRequested = false
        }
    }

    // 和 SettingsView 同一个约定：Tab/BackTab 走焦点链，手柄导航模式在
    // 页面激活期间打开，离开时恢复。
    StackView.onActivated: {
        if (SdlGamepadKeyNavigation.gamepadUiNavigationEnabled()) {
            SdlGamepadKeyNavigation.setUiNavMode(true)
        }

        // 进入页面拉一次设备快照（只读，安全可重复）；之后只由用户显式刷新。
        if (supported && authenticated) {
            KanadeController.refreshDevices()
        }

        if (SdlGamepadKeyNavigation.gamepadUiNavigationEnabled() &&
                SdlGamepadKeyNavigation.getConnectedGamepads() > 0) {
            focusFirstControl()
        }
    }

    StackView.onDeactivating: {
        SdlGamepadKeyNavigation.setUiNavMode(false)
        clearSecrets()
        // 这里故意什么都不取消。
        //
        // 起流时 StreamSegue 会盖在这一页上面，本页只是 deactivate，并没有
        // 被销毁。如果在这里 cancelOnlineSession()/logout()，一次正常的串流
        // 会被「切了个页面」直接掐断 —— 而串流期间的页面隐藏、手柄回到主界面、
        // 窗口失焦都不该影响已经成立的会话。
        //
        // 真正的清理放在下面的页面移除钩子里（那时页面确实不在了）。
    }

    // ---- 页面移除：真正的收尾 ----
    //
    // 与 Deactivating 的区别是关键：Deactivating 在 StreamSegue 盖上来时也会
    // 触发，那时会话必须继续跑；而页面被真正移除（弹栈、窗口关闭、进程退出）
    // 时，本页再也无法显示状态，继续持有运行时只会变成无人可管的孤儿。
    //
    // 因此这里只做一件事：请求控制器收尾。顺序是「先让本页失活，再请求」——
    // 这样即使 cancelOnlineSession() 内部同步发信号回来，本页也不会再渲染。
    // 控制器自己负责幂等与在途请求的丢弃（它对每次尝试有代际/运行号），
    // 所以重复调用或晚到回复都是安全的；本页不在这里做任何 wait 或阻塞。
    //
    // 两个钩子（onRemoved / onDestruction）都可能触发，所以本页自己也守一次：
    // 移除是一次性的，结束请求只发一次，绝不在收尾路径上重入。
    property bool runtimeEndRequested: false

    function endRuntimeOnRemoval() {
        if (page.runtimeEndRequested) {
            return
        }
        page.runtimeEndRequested = true
        if (!page.onlineRuntimeAvailable) {
            return
        }
        // 只取消「映射」，绝不 stopNativeApp()。
        //
        // stopNativeApp() 会走 m_native->stop() → NvHTTP::quitApp()，那是真的
        // 把主机上正在跑的应用退掉。页面被移除不应该有这种副作用：用户把本页
        // 弹栈、关窗、返回主界面，都不代表他要结束主机上的游戏 —— resume 场景
        // 尤其如此（应用还在跑，下次进来就是要接着恢复）。
        //
        // 因此清理只做一件事：撤销在线映射与会话（cancelOnlineSession 是
        // local-first 的，先停本端再尽力关远端）。停止主机应用只能由用户
        // 显式点「停止」触发。这里没有 fallback，也没有「反正要关了顺手停一下」。
        if (page.controllerHas("cancelOnlineSession")) {
            KanadeController.cancelOnlineSession()
        }
    }

    Component.onDestruction: page.endRuntimeOnRemoval()

    // StackView.pop()/replace() 移除本项时也会走到这里；与 onDestruction
    // 双保险，且同样只有在页面真的要离开时才成立。
    StackView.onRemoved: page.endRuntimeOnRemoval()

    // 工具栏「向下」或 StackView 切页会把焦点丢给这个壳，转交给第一个
    // 可操作控件，不停在看不见的死点上（和 SettingsView 同一处理）。
    onActiveFocusChanged: {
        if (activeFocus && Window.window && Window.window.activeFocusItem === page) {
            focusFirstControl()
        }
    }

    // ---- 密码输入框 ----
    //
    // 故意不继承 HardTextField。HardTextField 挂了 Keys.onMenuPressed →
    // window.gamepadOsk.openFor()，而 GamepadKeyboard.qml:30–32 会把
    // field.text 原样抄进它自己的缓冲框（第 104 行，一个不掩码的
    // HardTextField）。也就是说：走那条路的密码会明晃晃上屏。
    //
    // 所以密码与设备码不用屏幕键盘：外观和 HardTextField 一致，
    // 但不挂那个键。全局的 GamepadKeyboard 一行没动，别的页面
    // （IP、搜索、设置）照旧能调它。
    component SecretField: TextField {
        id: secretField

        color: Theme.text
        placeholderTextColor: Theme.textFaint
        selectByMouse: true
        hoverEnabled: true

        font.family: Theme.fontMono
        font.pointSize: Theme.fontBody

        leftPadding: Theme.spaceSm
        rightPadding: Theme.spaceSm
        topPadding: Theme.spaceXs
        bottomPadding: Theme.spaceXs

        echoMode: TextInput.Password
        // 掩码就是掩码：连「最后一个字符短暂显示」也不开
        passwordMaskDelay: 0
        // 输入法不记忆、不联想，也不把候选留在屏幕上
        inputMethodHints: Qt.ImhHiddenText | Qt.ImhSensitiveData |
                          Qt.ImhNoPredictiveText

        // 明确吞掉「呼出屏幕键盘」这个键。
        //
        // HardTextField 就是在这个键上开 OSK 的；不接这一路，键会继续上浮到
        // main.qml 的 StackView（它把同一个键映射成「打开设置」），在密码框上
        // 按一下 X 就会莫名切页。这里直接吃掉，密码框上什么都不发生。
        Keys.onMenuPressed: function(event) {
            event.accepted = true
        }

        background: Rectangle {
            implicitWidth: 120
            implicitHeight: 32

            radius: 0
            color: Theme.ink
            border.width: secretField.activeFocus ? 2 : 1
            border.color: secretField.activeFocus ? Theme.accent
                                                  : (secretField.hovered ? Theme.lineStrong
                                                                         : Theme.line)

            Behavior on border.color {
                ColorAnimation { duration: Theme.durFast }
            }
        }
    }

    SettingsScrollArea {
        id: scrollArea

        anchors {
            fill: parent
            // 让出顶部工具栏（56）+ 一格间距，和设置页一致
            topMargin: 72
            leftMargin: Theme.spaceLg
            rightMargin: Theme.spaceLg
            bottomMargin: Theme.spaceSm
        }

        Column {
            id: contentColumn
            width: parent.width
            spacing: Theme.spaceLg

            // 错误横幅：只显示白名单文案，永不回显原始错误。
            Panel {
                width: parent.width
                visible: page.errorText !== ""
                height: visible ? errorBannerText.implicitHeight + Theme.spaceMd * 2 : 0

                fill: Theme.surfaceLayer
                accentBarColor: Theme.danger
                accentBarWidth: Theme.accentBar

                Text {
                    id: errorBannerText
                    anchors {
                        left: parent.left
                        right: parent.right
                        top: parent.top
                        margins: Theme.spaceMd
                    }
                    text: page.errorText
                    color: Theme.text
                    font.family: Theme.fontSans
                    font.pointSize: Theme.fontRowTitle
                    wrapMode: Text.Wrap
                }
            }

            // 页头：先说清楚这一页管什么、不管什么。
            //
            // 当前构建不含在线控制面时，这里只剩一条「此版本没有」的说明；
            // 含控制面时，把「服务帐号」「在线授权」「能不能串流」三件事分开摆，
            // 并且永远把结论落在「数据面到底通没通」上，不留给用户猜。
            SettingsCard {
                title: qsTr("Kanade online mode")
                subtitle: page.supported
                          ? qsTr("Select Connect to request an online session. When the data path is ready, pair with Sunshine or select an app. Online mode never falls back to a local network address.")
                            + " " + qsTr("Online sessions do not send microphone audio. Your LAN microphone setting stays unchanged.")
                          : ""

                Text {
                    width: parent.width
                    visible: !page.supported
                    text: qsTr("Online mode is not available in this build. Devices on your local network work as before.")
                    color: Theme.textSettingsSubtitle
                    font.family: Theme.fontSans
                    font.pointSize: Theme.fontSettingsSubtitle
                    font.weight: Font.Medium
                    wrapMode: Text.Wrap
                }

                GridLayout {
                    width: parent.width
                    visible: page.supported
                    columns: 2
                    columnSpacing: Theme.spaceLg
                    rowSpacing: Theme.spaceSm

                    MicroLabel {
                        text: qsTr("Account")
                        Layout.minimumWidth: 120
                    }
                    Text {
                        Layout.fillWidth: true
                        text: page.authenticated && KanadeController.origin !== ""
                              ? KanadeController.origin
                              : qsTr("Not signed in")
                        // 地址是外部字符串，按纯文本画
                        textFormat: Text.PlainText
                        color: page.authenticated ? Theme.text : Theme.textDim
                        font.family: Theme.fontMono
                        font.pointSize: Theme.fontBody
                        wrapMode: Text.WrapAnywhere
                    }

                    MicroLabel {
                        text: qsTr("Online data path")
                        Layout.minimumWidth: 120
                        Layout.alignment: Qt.AlignTop
                        elide: Text.ElideNone
                        wrapMode: Text.Wrap
                    }
                    Text {
                        Layout.fillWidth: true
                        // 和会话卡、设备行读同一个接缝，不在这里另写一句常量，
                        // 免得三处各说各话。局域网列表是另一条路，不是回落 ——
                        // 文案把这两件事分开说。
                        text: page.headerDataPathText()
                        color: Theme.textFaint
                        font.family: Theme.fontSans
                        font.pointSize: Theme.fontBody
                        wrapMode: Text.Wrap
                    }
                }
            }

            SettingsCard {
                id: accountCard
                visible: page.supported
                title: qsTr("Service account")
                subtitle: page.authenticated
                          // SettingsCard 的副标题是共享组件里的 Text（没改它），
                          // 默认 AutoText；地址按纯文本转义后再拼进去。
                          ? qsTr("Signed in to %1").arg(page.asPlainText(KanadeController.origin))
                          : qsTr("Sign in to add and manage online devices. This does not change how local network devices work.")

                // ---- 未登录：登录表单 ----
                Column {
                    width: parent.width
                    visible: !page.authenticated
                    spacing: Theme.spaceMd

                    Column {
                        width: parent.width
                        spacing: Theme.spaceXs

                        MicroLabel {
                            text: qsTr("Service address")
                        }

                        HardTextField {
                            id: urlField
                            width: Math.min(parent.width, 420)
                            placeholderText: "https://kanade.example.com"
                            inputMethodHints: Qt.ImhUrlCharactersOnly
                            enabled: !KanadeController.busy
                            Accessible.name: qsTr("Service address")

                            Keys.onReturnPressed: page.submitLogin()
                            Keys.onEnterPressed: page.submitLogin()
                        }

                        Text {
                            id: urlError
                            visible: false
                            width: parent.width
                            text: qsTr("Enter the full HTTPS address of the service, e.g. https://kanade.example.com")
                            color: Theme.danger
                            font.family: Theme.fontSans
                            font.pointSize: Theme.fontBody
                            wrapMode: Text.Wrap
                        }
                    }

                    Column {
                        width: parent.width
                        spacing: Theme.spaceXs

                        MicroLabel {
                            text: qsTr("Login")
                        }

                        HardTextField {
                            id: loginField
                            width: Math.min(parent.width, 420)
                            placeholderText: qsTr("Account name")
                            enabled: !KanadeController.busy
                            Accessible.name: qsTr("Account name")

                            Keys.onReturnPressed: page.submitLogin()
                            Keys.onEnterPressed: page.submitLogin()
                        }
                    }

                    Column {
                        width: parent.width
                        spacing: Theme.spaceXs

                        MicroLabel {
                            text: qsTr("Password")
                        }

                        SecretField {
                            id: passwordField
                            width: Math.min(parent.width, 420)
                            placeholderText: qsTr("Password")
                            enabled: !KanadeController.busy
                            Accessible.name: qsTr("Password")

                            Keys.onReturnPressed: page.submitLogin()
                            Keys.onEnterPressed: page.submitLogin()
                        }

                        // 手柄用户在这里只能接物理键盘：本页密码框不挂屏幕键盘
                        // （那个键盘会把内容抄进不掩码的缓冲框）。所以不再提示
                        // 「按 X 打开屏幕键盘」——在密码框上它根本打不开。
                        Text {
                            width: parent.width
                            text: qsTr("Use a physical keyboard for passwords and device codes.")
                            color: Theme.textFaint
                            font.family: Theme.fontSans
                            font.pointSize: Theme.fontBody
                            wrapMode: Text.Wrap
                        }
                    }

                    HardProgress {
                        width: parent.width
                        visible: KanadeController.busy
                        running: KanadeController.busy
                    }

                    Flow {
                        width: parent.width
                        spacing: Theme.spaceSm

                        HardButton {
                            text: qsTr("Sign in")
                            primary: true
                            enabled: !KanadeController.busy &&
                                     urlField.text.trim() !== "" &&
                                     loginField.text !== "" &&
                                     passwordField.text !== ""

                            Keys.onReturnPressed: clicked()
                            Keys.onEnterPressed: clicked()

                            onClicked: page.submitLogin()
                        }

                        // 登录请求在飞时给一条明确的退路：退出即取消，
                        // 不用等超时。控制器把迟到回调按代际丢弃。
                        HardButton {
                            text: qsTr("Cancel sign-in")
                            visible: page.loginInFlight

                            Keys.onReturnPressed: clicked()
                            Keys.onEnterPressed: clicked()

                            onClicked: page.cancelLogin()
                        }
                    }
                }

                // ---- 已登录：状态与操作 ----
                Column {
                    width: parent.width
                    visible: page.authenticated
                    spacing: Theme.spaceMd

                    HardProgress {
                        width: parent.width
                        visible: KanadeController.busy
                        running: KanadeController.busy
                    }

                    Flow {
                        width: parent.width
                        spacing: Theme.spaceSm

                        HardButton {
                            id: refreshButton
                            text: qsTr("Refresh devices")
                            enabled: !KanadeController.busy
                            onClicked: KanadeController.refreshDevices()

                            Keys.onReturnPressed: clicked()
                            Keys.onEnterPressed: clicked()
                        }

                        // 退出不受 busy 限制：刷新、添加、移除在飞时也要能立刻走。
                        // 控制器负责取消在途请求并丢弃迟到回调。
                        HardButton {
                            id: signOutButton
                            text: qsTr("Sign out")

                            onClicked: {
                                // 记住地址方便下次登录；密码永远不留。
                                var previousOrigin = KanadeController.origin
                                page.clearSecrets()
                                KanadeController.logout()
                                if (urlField.text.trim() === "" && previousOrigin !== "") {
                                    urlField.text = previousOrigin
                                }
                            }

                            Keys.onReturnPressed: clicked()
                            Keys.onEnterPressed: clicked()
                        }

                        HardButton {
                            text: qsTr("Forget this installation")
                            enabled: !KanadeController.busy
                            onClicked: forgetInstallationDialog.open()

                            Keys.onReturnPressed: clicked()
                            Keys.onEnterPressed: clicked()
                        }
                    }

                    Text {
                        width: parent.width
                        text: qsTr("Signing out ends the session on this PC immediately, cancels work in progress, and keeps no password. It does not remove authorizations or Sunshine pairing on hosts.")
                        color: Theme.textFaint
                        font.family: Theme.fontSans
                        font.pointSize: Theme.fontBody
                        wrapMode: Text.Wrap
                    }
                }
            }

            SettingsCard {
                id: addDeviceCard
                visible: page.supported && page.authenticated
                title: qsTr("Add a device")
                subtitle: qsTr("Use the device code shown by the host. Adding a device creates an authorization only — it does not pair with Sunshine and does not open a stream.")

                Column {
                    width: parent.width
                    spacing: Theme.spaceMd

                    Column {
                        width: parent.width
                        spacing: Theme.spaceXs

                        MicroLabel {
                            text: qsTr("Device code")
                        }

                        SecretField {
                            id: codeField
                            width: Math.min(parent.width, 420)
                            placeholderText: qsTr("Code shown on the host")
                            enabled: !KanadeController.busy && !page.requestPending
                            Accessible.name: qsTr("Device code")

                            Keys.onReturnPressed: page.submitAddDevice()
                            Keys.onEnterPressed: page.submitAddDevice()
                        }
                    }

                    Column {
                        width: parent.width
                        spacing: Theme.spaceXs

                        MicroLabel {
                            text: qsTr("Approval method")
                        }

                        // 两种方式是一组互斥选择，所以做成同一排的选中态按钮，
                        // 而不是两个各自独立的主按钮。
                        Flow {
                            width: parent.width
                            spacing: Theme.spaceSm

                            HardButton {
                                text: qsTr("Device code + add password")
                                primary: page.addMethod === "password"
                                enabled: !KanadeController.busy && !page.requestPending
                                onClicked: page.addMethod = "password"

                                Keys.onReturnPressed: clicked()
                                Keys.onEnterPressed: clicked()
                            }

                            HardButton {
                                text: qsTr("Ask host to approve (device code required)")
                                primary: page.addMethod === "confirm"
                                enabled: !KanadeController.busy && !page.requestPending
                                onClicked: {
                                    page.addMethod = "confirm"
                                    // 切到主机批准就不再需要添加密码，清掉残留
                                    addPasswordField.text = ""
                                }

                                Keys.onReturnPressed: clicked()
                                Keys.onEnterPressed: clicked()
                            }
                        }

                        Text {
                            width: parent.width
                            text: page.addMethod === "confirm"
                                  ? qsTr("The host approves the same device code from its own Kanade companion. The device code is still required.")
                                  : qsTr("The host accepts the device code together with the add password.")
                            color: Theme.textFaint
                            font.family: Theme.fontSans
                            font.pointSize: Theme.fontBody
                            wrapMode: Text.Wrap
                        }
                    }

                    Column {
                        width: parent.width
                        spacing: Theme.spaceXs
                        visible: page.addMethod === "password"

                        MicroLabel {
                            text: qsTr("Add password")
                        }

                        SecretField {
                            id: addPasswordField
                            width: Math.min(parent.width, 420)
                            placeholderText: qsTr("Add password")
                            enabled: !KanadeController.busy && !page.requestPending
                            Accessible.name: qsTr("Add password")

                            Keys.onReturnPressed: page.submitAddDevice()
                            Keys.onEnterPressed: page.submitAddDevice()
                        }
                    }

                    Row {
                        spacing: Theme.spaceSm

                        HardButton {
                            text: qsTr("Add device")
                            primary: true
                            enabled: !KanadeController.busy &&
                                     !page.requestPending &&
                                     codeField.text.trim() !== "" &&
                                     (page.addMethod === "confirm" || addPasswordField.text !== "")

                            Keys.onReturnPressed: clicked()
                            Keys.onEnterPressed: clicked()

                            onClicked: page.submitAddDevice()
                        }
                    }

                    // 等待主机批准：给一条能立刻取消的出口。
                    // 可点与否由控制器判定，QML 不按 busy 提前锁死。
                    Panel {
                        width: parent.width
                        visible: page.requestPending
                        height: visible ? pendingRow.implicitHeight + Theme.spaceMd * 2 : 0

                        fill: Theme.surface2
                        accentBarColor: Theme.accent
                        accentBarWidth: Theme.accentBar

                        RowLayout {
                            id: pendingRow

                            anchors {
                                left: parent.left
                                right: parent.right
                                top: parent.top
                                margins: Theme.spaceMd
                            }
                            spacing: Theme.spaceMd

                            Column {
                                Layout.fillWidth: true
                                spacing: Theme.spaceXs

                                Text {
                                    width: parent.width
                                    text: page.pairStateText(KanadeController.pairState)
                                    color: Theme.text
                                    font.family: Theme.fontSans
                                    font.pointSize: Theme.fontRowTitle
                                    font.weight: Font.DemiBold
                                    wrapMode: Text.Wrap
                                }

                                Text {
                                    width: parent.width
                                    text: qsTr("You can cancel at any time; the request then ends on the service.")
                                    color: Theme.textDim
                                    font.family: Theme.fontSans
                                    font.pointSize: Theme.fontBody
                                    wrapMode: Text.Wrap
                                }
                            }

                            HardButton {
                                text: qsTr("Cancel request")

                                Keys.onReturnPressed: clicked()
                                Keys.onEnterPressed: clicked()

                                onClicked: KanadeController.cancelPair()
                            }
                        }
                    }

                    Text {
                        visible: !page.requestPending && text !== ""
                        width: parent.width
                        text: page.pairStateText(KanadeController.pairState)
                        color: Theme.textDim
                        font.family: Theme.fontSans
                        font.pointSize: Theme.fontBody
                        wrapMode: Text.Wrap
                    }
                }
            }

            // 在线会话：控制面进展与退出，永远不冒充串流。
            //
            // 只在控制器真的提供了会话接口时出现；没有接口的构建连这张卡
            // 都不显示，也不留一颗按不动的空按钮。
            SettingsCard {
                id: sessionCard
                visible: page.supported && page.authenticated && page.onlineRuntimeAvailable
                title: qsTr("Online session")
                subtitle: qsTr("Authorization, the online service session and the local online path are separate. This card never reports a video connection.")

                // 状态行：状态 + 结束时给原因的定性说明（不放原始错误）。
                GridLayout {
                    width: parent.width
                    columns: 2
                    columnSpacing: Theme.spaceMd
                    rowSpacing: Theme.spaceSm

                    MicroLabel {
                        text: qsTr("Session")
                        Layout.minimumWidth: 96
                        Layout.alignment: Qt.AlignTop
                    }
                    Text {
                        Layout.fillWidth: true
                        text: page.onlineStateText(page.onlineState)
                        color: page.onlineState === "failed" ? Theme.danger : Theme.text
                        font.family: Theme.fontSans
                        font.pointSize: Theme.fontBody
                        wrapMode: Text.Wrap
                    }

                    MicroLabel {
                        text: qsTr("Activation")
                        Layout.minimumWidth: 96
                        Layout.alignment: Qt.AlignTop
                    }
                    Text {
                        Layout.fillWidth: true
                        // 只有控制器明确确认过双端激活才写「已确认」；
                        // 其余一律「未确认」，不拿 active 推。
                        text: page.onlineActivationConfirmed
                              ? qsTr("Both ends confirmed this session")
                              : qsTr("Not confirmed yet")
                        color: page.onlineActivationConfirmed ? Theme.accent : Theme.textDim
                        font.family: Theme.fontSans
                        font.pointSize: Theme.fontBody
                        wrapMode: Text.Wrap
                    }

                    MicroLabel {
                        text: qsTr("Lease")
                        Layout.minimumWidth: 96
                        Layout.alignment: Qt.AlignTop
                    }
                    Text {
                        Layout.fillWidth: true
                        // 租约有效也只说明控制面还续得上，不代表端口组已绑定。
                        // 剩余时间不在这里做秒级倒计时：那是运行时的事，
                        // 而且会诱使人把「还有 90 秒」读成「已经连通」。
                        text: page.onlineLeaseValid
                              ? qsTr("Valid")
                              : qsTr("Not held")
                        color: page.onlineLeaseValid ? Theme.text : Theme.textDim
                        font.family: Theme.fontSans
                        font.pointSize: Theme.fontBody
                        wrapMode: Text.Wrap
                    }

                    MicroLabel {
                        text: qsTr("Data path")
                        Layout.minimumWidth: 96
                        Layout.alignment: Qt.AlignTop
                    }
                    Text {
                        Layout.fillWidth: true
                        // 只看 onlineReady（侧车 ready），不看 onlineState。
                        // 路径通了也只是先决条件，所以文案指向下一步，
                        // 不说「可以连接」。
                        text: page.dataPathStateText()
                        color: page.runtimePathReady ? Theme.text : Theme.textDim
                        font.family: Theme.fontSans
                        font.pointSize: Theme.fontBody
                        wrapMode: Text.Wrap
                    }
                }

                // 结束原因：只显示白名单内的定性句子。
                Text {
                    width: parent.width
                    visible: text !== ""
                    text: page.onlineStopReasonText(page.onlineStopReason)
                    color: Theme.textDim
                    font.family: Theme.fontSans
                    font.pointSize: Theme.fontBody
                    wrapMode: Text.Wrap
                }

                // 会话错误：白名单文案 + 一个「清除」出口，避免横幅永久占位。
                Panel {
                    width: parent.width
                    visible: page.onlineErrorText !== ""
                    height: visible ? sessionErrorText.implicitHeight + Theme.spaceMd * 2 : 0

                    fill: Theme.surface2
                    accentBarColor: Theme.danger
                    accentBarWidth: Theme.accentBar

                    RowLayout {
                        anchors {
                            left: parent.left
                            right: parent.right
                            top: parent.top
                            margins: Theme.spaceMd
                        }
                        spacing: Theme.spaceMd

                        Text {
                            id: sessionErrorText
                            Layout.fillWidth: true
                            text: page.onlineErrorText
                            color: Theme.text
                            font.family: Theme.fontSans
                            font.pointSize: Theme.fontBody
                            wrapMode: Text.Wrap
                        }

                        HardButton {
                            text: qsTr("Dismiss")
                            visible: page.controllerHas("clearOnlineError")

                            Keys.onReturnPressed: clicked()
                            Keys.onEnterPressed: clicked()

                            onClicked: {
                                // 处理器体在点击时才求值；这里再挡一次，
                                // 免得程序化触发在方法缺席的构建里抛异常。
                                if (page.controllerHas("clearOnlineError")) {
                                    KanadeController.clearOnlineError()
                                }
                            }
                        }
                    }
                }

                // 会话动作：结束是页面层唯一真实可做的事。
                // 「开始」按设备走，放在设备行里 —— 它需要那一条的
                // grantId 和 hostId，页面层拿不到单个设备的选择。
                Flow {
                    width: parent.width
                    spacing: Theme.spaceSm

                    HardButton {
                        text: qsTr("End online session")
                        visible: page.canCancelOnline

                        Keys.onReturnPressed: clicked()
                        Keys.onEnterPressed: clicked()

                        onClicked: {
                            // canCancelOnline 已经把「方法是否存在」算进去了；
                            // 点击时再挡一次，和「关闭」用同一个规矩。
                            if (page.controllerHas("cancelOnlineSession")) {
                                KanadeController.cancelOnlineSession()
                            }
                        }
                    }
                }
            }

            // 原生配对与原应用：真正会碰宿主的这一段。
            //
            // 只在线上路经准备好之后才出现 —— 没准备好时连卡片都不画，
            // 免得给一个按不动的入口。配对和起流是两件事：
            // 先拿证书，再拉应用列表，最后才可能起流。
            SettingsCard {
                id: nativeCard
                // nativeAvailable() 在控制器里就是 onlineReady && m_native != nullptr，
                // 而后一个条件 QML 看不到。所以这里用 onlineReady 当门；
                // 万一 m_native 为 null，按钮点击会被控制器拒绝并把
                // nativePairingState 打成 unavailable，界面照实显示，
                // 不会留下「按了没反应」的假象。
                visible: page.onlineRuntimeAvailable && page.runtimePathReady
                title: qsTr("Sunshine pairing")
                subtitle: qsTr("Pairing here uses the host's own PIN exchange. The PIN is generated for this attempt and shown only while it is running.")

                GridLayout {
                    width: parent.width
                    columns: 2
                    columnSpacing: Theme.spaceMd
                    rowSpacing: Theme.spaceSm

                    MicroLabel {
                        text: qsTr("Native path")
                        Layout.minimumWidth: 96
                        Layout.alignment: Qt.AlignTop
                    }
                    Text {
                        Layout.fillWidth: true
                        text: page.nativeStateText(page.nativeState)
                        color: page.nativeState === "failed" ? Theme.danger : Theme.text
                        font.family: Theme.fontSans
                        font.pointSize: Theme.fontBody
                        wrapMode: Text.Wrap
                    }

                    // PIN：只在本次配对进行中显示，且一定是 C++ 生成的那个。
                    // 这里没有输入框 —— 手输 PIN 不存在于在线路径。
                    MicroLabel {
                        text: qsTr("PIN")
                        Layout.minimumWidth: 96
                        Layout.alignment: Qt.AlignTop
                        visible: page.nativePinVisible
                    }
                    Text {
                        Layout.fillWidth: true
                        visible: page.nativePinVisible
                        text: page.nativePinText
                        // 等宽大字：要能隔着一米照着念给另一台机器
                        color: Theme.accent
                        font.family: Theme.fontMono
                        font.pointSize: Theme.fontHeroTitle
                        font.weight: Font.Bold
                        wrapMode: Text.Wrap
                    }
                }

                // PIN 的说明只在显示时出现，避免常态占位。
                Text {
                    width: parent.width
                    visible: page.nativePinVisible
                    text: qsTr("Enter this PIN in Sunshine's own web UI on the host. It is not saved and disappears when pairing ends.")
                    color: Theme.textDim
                    font.family: Theme.fontSans
                    font.pointSize: Theme.fontBody
                    wrapMode: Text.Wrap
                }

                Text {
                    width: parent.width
                    visible: page.nativeErrorDisplay !== ""
                    text: page.nativeErrorDisplay
                    color: Theme.danger
                    font.family: Theme.fontSans
                    font.pointSize: Theme.fontBody
                    wrapMode: Text.Wrap
                }

                HardProgress {
                    width: parent.width
                    visible: page.nativeBusy
                    running: page.nativeBusy
                }

                Flow {
                    width: parent.width
                    spacing: Theme.spaceSm

                    HardButton {
                        text: qsTr("Pair with the host")
                        primary: true
                        // 可见 ⇔ 可点。nativeCanPair 已经把 busy、证书是否已
                        // 拿到（failed 的两种分支）都算进去了，所以这里直接用
                        // 它，不再另写一套 visible 表达式 —— 否则会出现
                        // 「看得见但按不动」的按钮。
                        // pairing 期间按钮保持可见（busy 让它是灰的），
                        // 免得进度条下面的按钮突然消失。
                        visible: page.nativeCanPair || page.nativeState === "pairing"
                        enabled: page.nativeCanPair

                        Keys.onReturnPressed: clicked()
                        Keys.onEnterPressed: clicked()

                        onClicked: KanadeController.beginNativePairing()
                    }

                    HardButton {
                        text: qsTr("Load apps")
                        // failed 时只有证书已就位才该出现（那种失败是拉列表挂了，
                        // 重试的语义是「再拉一次」）。证书没拿到时这里保持隐藏，
                        // 由上面的「与主机配对」接手。
                        visible: page.nativeCanLoadApps || page.nativeState === "loadingApps"
                        enabled: page.nativeCanLoadApps

                        Keys.onReturnPressed: clicked()
                        Keys.onEnterPressed: clicked()

                        onClicked: KanadeController.refreshNativeApps()
                    }

                    HardButton {
                        text: qsTr("Stop")
                        // 「停止」是本段唯一会改动主机状态的动作（它会调用
                        // 宿主 quitApp），所以只有真的在跑着一段时才出现：
                        // 已配对、应用列表在手，或正在配对/加载（中途退出）。
                        // pinRejected / failed / stopped 不给这颗按钮 ——
                        // 那时没有运行中的东西可停。
                        visible: page.nativeState === "paired" ||
                                 page.nativeState === "appsReady" ||
                                 page.nativeState === "pairing" ||
                                 page.nativeState === "loadingApps"
                        // busy 期间也可点：这是配对或加载卡住时唯一的退路。
                        // stopNativeApp() 会先递增运行代际，在途结果随即作废
                        // （见控制器实现），所以中途停止是安全的。
                        enabled: page.nativeState !== "idle" &&
                                 page.nativeState !== "unavailable"

                        Keys.onReturnPressed: clicked()
                        Keys.onEnterPressed: clicked()

                        onClicked: KanadeController.stopNativeApp()
                    }
                }

                // 应用列表：只显示 appId 与名字，不显示地址、不显示端口。
                // 起流按钮只有在真的拿到会话时才 push 加载页（见 startNativeStream）。
                Repeater {
                    model: page.nativeApps
                    visible: false

                    delegate: Item {
                        id: nativeAppRow
                        width: parent ? parent.width : 0
                        height: nativeAppLayout.implicitHeight + Theme.spaceSm

                        readonly property string appId:
                            modelData.appId !== undefined ? String(modelData.appId) : ""
                        readonly property string appName:
                            (modelData.name !== undefined && modelData.name !== "")
                            ? String(modelData.name) : qsTr("Unnamed app")

                        GridLayout {
                            id: nativeAppLayout
                            anchors {
                                left: parent.left
                                right: parent.right
                                top: parent.top
                            }
                            columns: 2
                            columnSpacing: Theme.spaceMd

                            Text {
                                Layout.fillWidth: true
                                text: nativeAppRow.appName
                                textFormat: Text.PlainText
                                color: Theme.text
                                font.family: Theme.fontSans
                                font.pointSize: Theme.fontBody
                                elide: Text.ElideRight
                                verticalAlignment: Text.AlignVCenter
                            }

                            HardButton {
                                text: qsTr("Start")
                                enabled: page.nativeCanStream

                                Keys.onReturnPressed: clicked()
                                Keys.onEnterPressed: clicked()

                                onClicked: page.startNativeStream(nativeAppRow.appId,
                                                                  nativeAppRow.appName)
                            }
                        }
                    }
                }

                // 列表空但已就绪时给一句话，而不是一片空白。
                Text {
                    width: parent.width
                    visible: page.nativeState === "appsReady" &&
                             (!page.nativeApps || page.nativeApps.length === 0)
                    text: qsTr("The host returned no apps.")
                    color: Theme.textDim
                    font.family: Theme.fontSans
                    font.pointSize: Theme.fontBody
                    wrapMode: Text.Wrap
                }
            }

            SettingsCard {
                id: devicesCard
                visible: page.supported && page.authenticated
                title: qsTr("Devices")
                subtitle: qsTr("Devices authorized with this installation. Removing an authorization never changes Sunshine pairing on the host.")

                Text {
                    width: parent.width
                    visible: !KanadeController.devices || KanadeController.devices.length === 0
                    text: qsTr("No devices added yet. Adding a device works with the device code shown on the host.")
                    color: Theme.textDim
                    font.family: Theme.fontSans
                    font.pointSize: Theme.fontBody
                    wrapMode: Text.Wrap
                }

                Repeater {
                    model: KanadeController.devices
                    // Repeater 自己是零尺寸的可见 Item，Column 会给它留一格
                    // 间距。delegate 挂在父级 Column 上、不受影响，所以把它
                    // 自己藏起来。
                    visible: false

                    delegate: Item {
                        id: deviceRow
                        width: parent ? parent.width : 0
                        height: deviceLayout.implicitHeight + Theme.spaceMd

                        // 主机名是服务端给的字符串，永远按纯文本渲染：
                        // 不解析标签、不加载图片、不跟随链接。
                        readonly property string deviceName:
                            (modelData.name !== undefined && modelData.name !== "")
                            ? String(modelData.name) : qsTr("Unnamed host")

                        Rectangle {
                            anchors {
                                left: parent.left
                                right: parent.right
                                bottom: parent.bottom
                            }
                            height: 1
                            color: Theme.line
                            // 最后一行不画分隔线，避免和卡片下沿贴出双线
                            visible: deviceRow.parent &&
                                     deviceRow.parent.children[deviceRow.parent.children.length - 1] !== deviceRow
                        }

                        GridLayout {
                            id: deviceLayout
                            anchors {
                                left: parent.left
                                right: parent.right
                                top: parent.top
                                leftMargin: Theme.spaceMd
                                rightMargin: Theme.spaceMd
                                topMargin: Theme.spaceMd
                            }
                            columns: deviceRow.width < Theme.settingsRowStackBreakpoint ? 1 : 2
                            columnSpacing: Theme.spaceLg
                            rowSpacing: Theme.spaceSm

                            Column {
                                Layout.fillWidth: true
                                spacing: Theme.spaceXs

                                Text {
                                    width: parent.width
                                    text: deviceRow.deviceName
                                    // 服务端给的主机名按纯文本画，不解释成富文本
                                    textFormat: Text.PlainText
                                    color: Theme.text
                                    font.family: Theme.fontSans
                                    font.pointSize: Theme.fontRowTitle
                                    font.weight: Font.DemiBold
                                    elide: Text.ElideRight
                                }

                                // 四种状态分行显示，互不冒充：
                                // 已添加授权 ≠ 会话在跑 ≠ 原生已配对 ≠ 可串流。
                                GridLayout {
                                    columns: 2
                                    columnSpacing: Theme.spaceMd
                                    rowSpacing: Theme.spaceXs

                                    MicroLabel {
                                        text: qsTr("Authorization")
                                        Layout.minimumWidth: 96
                                    }
                                    Text {
                                        text: qsTr("Added")
                                        color: Theme.accent
                                        font.family: Theme.fontSans
                                        font.pointSize: Theme.fontBody
                                    }

                                    MicroLabel {
                                        text: qsTr("Kanade session")
                                        Layout.minimumWidth: 96
                                    }
                                    Text {
                                        text: page.connectionStateText(modelData.connectionState)
                                        color: Theme.textDim
                                        font.family: Theme.fontSans
                                        font.pointSize: Theme.fontBody
                                        wrapMode: Text.Wrap
                                        Layout.fillWidth: true
                                    }

                                    MicroLabel {
                                        text: qsTr("Native pairing")
                                        Layout.minimumWidth: 96
                                    }
                                    // 云端观测不到 Sunshine 原生配对；真实结果只能
                                    // 来自选定端点的原生配对流程，所以这里守 unknown。
                                    Text {
                                        text: page.nativePairingText(modelData.nativePairing)
                                        color: Theme.textDim
                                        font.family: Theme.fontSans
                                        font.pointSize: Theme.fontBody
                                        wrapMode: Text.Wrap
                                        Layout.fillWidth: true
                                    }

                                    MicroLabel {
                                        text: qsTr("Data path")
                                        Layout.minimumWidth: 96
                                    }
                                    // 这一栏只认运行时的 onlineReady（侧车真的
                                    // 报 ready），不看上面的授权/会话/原生配对。
                                    // 这里也不显示 onlineState 的文本 ——
                                    // 那是控制面会话，不是路径也不是画面。
                                    Text {
                                        text: page.dataPathStateText()
                                        color: page.runtimePathReady ? Theme.text : Theme.textDim
                                        font.family: Theme.fontSans
                                        font.pointSize: Theme.fontBody
                                        wrapMode: Text.Wrap
                                        Layout.fillWidth: true
                                    }
                                }
                            }

                            Column {
                                Layout.alignment: Qt.AlignTop | Qt.AlignRight
                                spacing: Theme.spaceSm

                                HardButton {
                                    text: qsTr("Remove")
                                    enabled: !KanadeController.busy

                                    onClicked: {
                                        removeGrantDialog.grantId = modelData.grantId
                                        removeGrantDialog.deviceName =
                                            page.asPlainText(deviceRow.deviceName)
                                        removeGrantDialog.open()
                                    }

                                    Keys.onReturnPressed: clicked()
                                    Keys.onEnterPressed: clicked()
                                }

                                // 在线会话必须在数据路径 ready 之前启动；ready 是
                                // 启动会话后的结果。控制器只对匹配运行时的授权行开放，
                                // 并在任何活动/收尾会话期间关闭重复入口。
                                //
                                // 参数只有这一行的 grantId 和 hostId —— 两者都来自
                                // GET /v1/devices。对端安装 ID、key version、公钥
                                // 由本机预配置的 peer manifest 提供，QML 不传也不看，
                                // 所以界面不可能把身份绑到别的机器上。
                                //
                                // 状态和设备列表属性在表达式里显式读取，分别依赖
                                // onlineChanged 与 devicesChanged；controller 的精确行
                                // 检查负责匹配已配置的 host/grant。
                                HardButton {
                                    text: qsTr("Connect")
                                    enabled: page.authenticated && page.onlineRuntimeAvailable &&
                                             page.onlineState !== "closing" &&
                                             page.deviceSnapshotContains(modelData.grantId,
                                                                         modelData.hostId) &&
                                             page.controllerHas("canStartOnlineSessionForGrant") &&
                                             KanadeController.canStartOnlineSessionForGrant(
                                                 modelData.grantId, modelData.hostId)

                                    onClicked: {
                                        if (page.controllerHas("canStartOnlineSessionForGrant") &&
                                                KanadeController.canStartOnlineSessionForGrant(
                                                    modelData.grantId, modelData.hostId) &&
                                                page.controllerHas("startOnlineSessionForGrant")) {
                                            KanadeController.startOnlineSessionForGrant(
                                                modelData.grantId, modelData.hostId)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 收尾说明：把「不会自动换路」和「不会自动复活」写在页面上，
            // 不用户去翻文档。
            Panel {
                width: parent.width
                visible: page.supported && page.authenticated
                height: visible ? footerNote.implicitHeight + Theme.spaceMd * 2 : 0

                fill: Theme.surfaceLayer
                accentBarColor: Theme.lineStrong
                accentBarWidth: Theme.accentBar

                Text {
                    id: footerNote
                    anchors {
                        left: parent.left
                        right: parent.right
                        top: parent.top
                        margins: Theme.spaceMd
                    }
                    text: qsTr("If an authorization ends, is removed, or the service cannot be reached, this page stops. It never switches to a local network address and never restores an earlier stream on its own.")
                    color: Theme.textDim
                    font.family: Theme.fontSans
                    font.pointSize: Theme.fontBody
                    wrapMode: Text.Wrap
                }
            }

            // 「被盖住」和「被移除」在这里是两种不同结果，必须写清楚：
            // 起流时 StreamSegue 只是盖住本页，会话继续；而本页被真正移除
            // （弹栈、关闭窗口）时运行时会收尾。免得用户以为「离开这一页」
            // 一定等于停流，或反过来以为永远停不掉。
            Text {
                width: parent.width
                visible: page.supported && page.authenticated && page.onlineRuntimeAvailable
                text: qsTr("A stream covers this page without ending the online session. Closing this page does end it. The end action and signing out also end it.")
                color: Theme.textFaint
                font.family: Theme.fontSans
                font.pointSize: Theme.fontBody
                wrapMode: Text.Wrap
            }
        }
    }

    NavigableMessageDialog {
        id: removeGrantDialog

        property string grantId: ""
        // 已经按纯文本转义过的显示名（见 asPlainText）。
        property string deviceName: ""

        text: qsTr("Remove the authorization for '%1'? The host must share a new device code before it can be added again. Sunshine pairing on the host is not affected.").arg(deviceName)
        standardButtons: Dialog.Ok | Dialog.Cancel

        onAccepted: KanadeController.removeGrant(grantId)

        onClosed: {
            grantId = ""
            deviceName = ""
        }
    }

    NavigableMessageDialog {
        id: forgetInstallationDialog

        text: qsTr("Forget this installation? This PC's identity for the service is removed and you are signed out. Authorizations granted to this installation stop working here. Nothing is revoked on the service itself.")
        standardButtons: Dialog.Ok | Dialog.Cancel

        onAccepted: {
            page.clearSecrets()
            KanadeController.forgetInstallation()
        }
    }
}
