package br.com.nexodev.ownerlock;

import com.mojang.brigadier.arguments.IntegerArgumentType;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.tree.LiteralCommandNode;
import io.papermc.paper.command.brigadier.CommandSourceStack;
import io.papermc.paper.command.brigadier.Commands;
import io.papermc.paper.event.player.AsyncChatEvent;
import io.papermc.paper.plugin.lifecycle.event.types.LifecycleEvents;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.configuration.file.YamlConfiguration;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Base64;
import java.util.Deque;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * OwnerLock for Paper 26.3.
 * In online mode, owner identity is verified by configured UUID plus configured name.
 * In offline mode, the name is only an identifier: a PBKDF2 secret is required,
 * operator status is session-only, and stale operator entries are cleaned on startup.
 */
public final class OwnerLockPlugin extends JavaPlugin implements Listener {
    private static final int SECRET_MIN_LENGTH = 16;
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int HASH_BITS = 256;
    private static final int SALT_BYTES = 16;
    private static final int MAX_STORED_ITERATIONS = 1_000_000;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final Set<UUID> authenticatedSessions = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<UUID, PendingLogin> pendingLogins = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AttemptState> attemptsByAddress = new ConcurrentHashMap<>();

    private volatile byte[] secretSalt;
    private volatile byte[] secretHash;
    private volatile int secretIterations;
    private String ownerName;
    private UUID ownerUuid;
    private boolean onlineMode;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        onlineMode = getServer().getOnlineMode();

        if (!loadOwnerSettings()) {
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        if (!onlineMode && !initializeSecretStore()) {
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        getServer().getPluginManager().registerEvents(this, this);
        getLifecycleManager().registerEventHandler(LifecycleEvents.COMMANDS, event ->
                event.registrar().register(buildCommandTree(), "OwnerLock owner-only administration")
        );

        if (!onlineMode) {
            // Remove an operator entry left in ops.json after a crash before the owner reconnects.
            OfflinePlayer offlineOwner = Bukkit.getOfflinePlayer(ownerName);
            if (offlineOwner.isOp()) {
                offlineOwner.setOp(false);
                getLogger().warning("Removed stale offline-mode OP for configured owner " + ownerName + ".");
            }
        }

        // Also handle a plugin reload while the owner is already connected.
        for (Player onlinePlayer : Bukkit.getOnlinePlayers()) {
            if (onlineMode && isConfiguredOnlineOwner(onlinePlayer)) {
                authenticatedSessions.add(onlinePlayer.getUniqueId());
                if (getConfig().getBoolean("auto-op-online", true) && !onlinePlayer.isOp()) {
                    onlinePlayer.setOp(true);
                    audit(onlinePlayer, "online UUID+name verified on plugin enable; OP granted");
                }
            } else if (!onlineMode && isConfiguredOwnerName(onlinePlayer)) {
                if (onlinePlayer.isOp()) onlinePlayer.setOp(false);
                onlinePlayer.sendMessage("§8[§bOwnerLock§8] §eUse /ownerctl login para iniciar uma nova sessão autenticada.");
            }
        }

        getLogger().info("OwnerLock " + getDescription().getVersion() + " enabled; online-mode=" + onlineMode
                + "; commands registered with Paper's lifecycle command API.");
        if (!onlineMode) {
            getLogger().warning("OFFLINE MODE: username/UUID are not proof of identity. Keep this test server private.");
        }
    }

    @Override
    public void onDisable() {
        if (!onlineMode && ownerName != null && ownerName.matches("[A-Za-z0-9_]{3,16}")) {
            for (Player player : Bukkit.getOnlinePlayers()) {
                if (isConfiguredOwnerName(player)) {
                    player.setOp(false);
                }
            }
            // Also clear the persisted offline UUID's operator status on normal shutdown.
            try {
                Bukkit.getOfflinePlayer(ownerName).setOp(false);
            } catch (RuntimeException exception) {
                getLogger().warning("Could not clean offline OP entry: " + exception.getMessage());
            }
        }
        authenticatedSessions.clear();
        pendingLogins.clear();
    }

    private boolean loadOwnerSettings() {
        ownerName = getConfig().getString("owner-name", "").trim();
        String uuidText = getConfig().getString("owner-uuid", "").trim();

        if (ownerName.isBlank() || ownerName.equalsIgnoreCase("COLOQUE-SEU-NICK-AQUI")
                || !ownerName.matches("[A-Za-z0-9_]{3,16}")) {
            getLogger().severe("Configure owner-name com um nick Minecraft válido (3 a 16 caracteres) em plugins/OwnerLock/config.yml.");
            return false;
        }

        ownerUuid = null;
        if (!uuidText.isBlank() && !uuidText.equalsIgnoreCase("COLOQUE-SEU-UUID-AQUI")) {
            try {
                ownerUuid = UUID.fromString(uuidText);
            } catch (IllegalArgumentException exception) {
                getLogger().severe("owner-uuid não é um UUID válido.");
                return false;
            }
        }

        if (onlineMode && ownerUuid == null) {
            getLogger().severe("online-mode=true exige owner-uuid com o UUID oficial da conta proprietária. Plugin desativado.");
            return false;
        }
        if (!onlineMode && ownerUuid == null) {
            getLogger().warning("owner-uuid não foi configurado. Ele não autentica jogadores em modo offline; a senha é obrigatória.");
        }
        return true;
    }

    /**
     * Imports a configured plaintext secret once, saves a salted PBKDF2 hash to auth.yml,
     * then clears owner-secret from config.yml. A non-empty value can be set again to rotate it.
     */
    private boolean initializeSecretStore() {
        Path authPath = getDataFolder().toPath().resolve("auth.yml");
        try {
            Files.createDirectories(authPath.getParent());
        } catch (IOException exception) {
            getLogger().severe("Could not create plugin folder: " + exception.getMessage());
            return false;
        }

        String configuredSecret = getConfig().getString("owner-secret", "");
        boolean placeholder = isSecretPlaceholder(configuredSecret);
        if (configuredSecret != null && !configuredSecret.isBlank() && !placeholder) {
            if (configuredSecret.length() < SECRET_MIN_LENGTH) {
                getLogger().severe("owner-secret precisa ter pelo menos " + SECRET_MIN_LENGTH + " caracteres. Plugin desativado.");
                return false;
            }
            byte[] newSalt = new byte[SALT_BYTES];
            SECURE_RANDOM.nextBytes(newSalt);
            try {
                byte[] newHash = deriveSecret(configuredSecret, newSalt, PBKDF2_ITERATIONS);
                YamlConfiguration auth = new YamlConfiguration();
                auth.set("secret.salt", Base64.getEncoder().encodeToString(newSalt));
                auth.set("secret.hash", Base64.getEncoder().encodeToString(newHash));
                auth.set("secret.iterations", PBKDF2_ITERATIONS);
                auth.save(authPath.toFile());

                // Only clear plaintext after the hash was written successfully.
                getConfig().set("owner-secret", "");
                saveConfig();
                secretSalt = newSalt;
                secretHash = newHash;
                secretIterations = PBKDF2_ITERATIONS;
                getLogger().info("Offline owner secret converted to a salted PBKDF2 hash and removed from config.yml.");
                return true;
            } catch (IOException | GeneralSecurityException exception) {
                getLogger().severe("Could not safely save owner authentication data: " + exception.getMessage());
                return false;
            }
        }

        if (!Files.isRegularFile(authPath)) {
            getLogger().severe("Modo offline exige owner-secret com pelo menos " + SECRET_MIN_LENGTH
                    + " caracteres na primeira inicialização. Depois o plugin guarda apenas o hash em auth.yml.");
            return false;
        }

        YamlConfiguration auth = YamlConfiguration.loadConfiguration(authPath.toFile());
        try {
            String saltText = auth.getString("secret.salt", "");
            String hashText = auth.getString("secret.hash", "");
            int iterations = auth.getInt("secret.iterations", 0);
            byte[] salt = Base64.getDecoder().decode(saltText);
            byte[] hash = Base64.getDecoder().decode(hashText);
            if (salt.length < SALT_BYTES || hash.length != HASH_BITS / 8
                    || iterations < 100_000 || iterations > MAX_STORED_ITERATIONS) {
                throw new IllegalArgumentException("auth.yml contém parâmetros inválidos");
            }
            secretSalt = salt;
            secretHash = hash;
            secretIterations = iterations;
            return true;
        } catch (IllegalArgumentException exception) {
            getLogger().severe("auth.yml inválido ou corrompido. Defina uma nova owner-secret em config.yml: " + exception.getMessage());
            return false;
        }
    }

    private boolean isSecretPlaceholder(String secret) {
        if (secret == null || secret.isBlank()) return true;
        String value = secret.toLowerCase(Locale.ROOT);
        return value.contains("troque-por") || value.contains("coloque-seu")
                || value.equals("changeme") || value.equals("change-me") || value.equals("secret");
    }

    private byte[] deriveSecret(String secret, byte[] salt, int iterations) throws GeneralSecurityException {
        char[] passwordChars = secret.toCharArray();
        PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, iterations, HASH_BITS);
        Arrays.fill(passwordChars, '\0');
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private boolean verifySecret(String supplied) {
        if (supplied == null || secretHash == null || secretSalt == null) return false;
        try {
            byte[] candidate = deriveSecret(supplied, secretSalt, secretIterations);
            return MessageDigest.isEqual(secretHash, candidate);
        } catch (GeneralSecurityException exception) {
            getLogger().severe("Secret verification failed: " + exception.getMessage());
            return false;
        }
    }

    @EventHandler(priority = EventPriority.NORMAL)
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        if (onlineMode) {
            if (isConfiguredOnlineOwner(player)) {
                authenticatedSessions.add(player.getUniqueId());
                if (getConfig().getBoolean("auto-op-online", true) && !player.isOp()) {
                    player.setOp(true);
                    audit(player, "online UUID+name verified; OP granted");
                }
                player.sendMessage("§8[§bOwnerLock§8] §aConta proprietária verificada pelo UUID oficial.");
            }
            return;
        }

        if (isConfiguredOwnerName(player)) {
            // Do not allow offline ops.json entries to bypass the password gate.
            if (player.isOp()) {
                player.setOp(false);
                audit(player, "offline OP removed pending password authentication");
            }
            player.sendMessage("§8[§bOwnerLock§8] §eServidor em modo offline: o nick não comprova identidade.");
            player.sendMessage("§7Use §f/ownerctl login §7e envie a senha na próxima mensagem do chat.");
            player.sendMessage("§7A mensagem de senha será cancelada, mas outros plugins de chat ainda podem registrá-la.");
        }
    }

    @EventHandler(priority = EventPriority.NORMAL)
    public void onQuit(PlayerQuitEvent event) {
        Player player = event.getPlayer();
        UUID id = player.getUniqueId();
        pendingLogins.remove(id);
        authenticatedSessions.remove(id);

        if (!onlineMode && isConfiguredOwnerName(player)) {
            // OP is intentionally session-only in offline mode, including if another plugin altered it.
            player.setOp(false);
            audit(player, "offline session ended; temporary OP revoked");
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onSecretChat(AsyncChatEvent event) {
        UUID playerId = event.getPlayer().getUniqueId();
        PendingLogin pending = pendingLogins.get(playerId);
        if (pending == null || !pendingLogins.remove(playerId, pending)) return;

        // Cancel before any normal broadcast. Third-party logging plugins may still inspect cancelled events.
        event.setCancelled(true);
        String supplied = PlainTextComponentSerializer.plainText().serialize(event.message());
        long now = System.currentTimeMillis();

        if (now > pending.expiresAtMillis()) {
            runMain(() -> messageIfOnline(playerId, "§cPedido de login expirou. Use /ownerctl login novamente."));
            return;
        }
        if (isLocked(pending.attemptKey(), now)) {
            runMain(() -> messageIfOnline(playerId, "§cLogin temporariamente bloqueado. Aguarde antes de tentar novamente."));
            return;
        }

        boolean valid = verifySecret(supplied);
        if (valid) {
            attemptsByAddress.remove(pending.attemptKey());
            runMain(() -> completeOfflineLogin(playerId, pending));
        } else {
            runMain(() -> {
                AttemptResult result = noteFailure(pending.attemptKey(), System.currentTimeMillis());
                Player player = Bukkit.getPlayer(playerId);
                if (player == null || !player.isOnline()) return;
                if (result.locked()) {
                    audit(player, "offline login locked after failed attempts");
                    player.sendMessage("§cMuitas tentativas. Aguarde " + result.lockSeconds() + " segundos antes de tentar novamente.");
                } else {
                    audit(player, "offline login failed (attempt " + result.failures() + ")");
                    player.sendMessage("§cSenha incorreta. Tentativa " + result.failures() + "/" + result.limit() + ".");
                }
            });
        }
    }

    private void runMain(Runnable task) {
        if (!isEnabled()) return;
        try {
            Bukkit.getScheduler().runTask(this, task);
        } catch (RuntimeException ignored) {
            // Plugin may be shutting down between the async chat event and this callback.
        }
    }

    private void completeOfflineLogin(UUID playerId, PendingLogin pending) {
        Player player = Bukkit.getPlayer(playerId);
        if (player == null || player != pending.playerReference() || !player.isOnline()
                || onlineMode || !isConfiguredOwnerName(player)) return;

        authenticatedSessions.add(playerId);
        boolean grantOp = getConfig().getBoolean("auto-op-offline", true);
        if (grantOp && !player.isOp()) player.setOp(true);
        audit(player, "offline password authentication successful; admin session started");
        player.sendMessage("§8[§bOwnerLock§8] §aSenha confirmada. Sessão administrativa ativada.");
        if (grantOp) player.sendMessage("§7OP temporária ativa até desconectar ou usar /ownerctl logout.");
        player.sendMessage("§7Comando de console: §f/ownerctl console <comando>");
    }

    private void messageIfOnline(UUID playerId, String message) {
        Player player = Bukkit.getPlayer(playerId);
        if (player != null && player.isOnline()) player.sendMessage(message);
    }

    private void beginOfflineLogin(Player player) {
        if (!isConfiguredOwnerName(player)) {
            player.sendMessage("§cEsse nick não está autorizado a iniciar a autenticação.");
            return;
        }
        if (hasAdminAccess(player)) {
            player.sendMessage("§aSua sessão administrativa já está ativa.");
            return;
        }

        String key = addressKey(player);
        long now = System.currentTimeMillis();
        if (isLocked(key, now)) {
            player.sendMessage("§cLogin temporariamente bloqueado. Aguarde antes de tentar novamente.");
            return;
        }
        int windowSeconds = Math.max(10, Math.min(120, getConfig().getInt("login-window-seconds", 45)));
        PendingLogin pending = new PendingLogin(now + windowSeconds * 1000L, key, player);
        pendingLogins.put(player.getUniqueId(), pending);
        player.sendMessage("§eEnvie sua senha como a próxima mensagem no chat em até " + windowSeconds + " segundos.");
        player.sendMessage("§7O OwnerLock cancela essa mensagem, mas plugins externos ainda podem registrar eventos de chat cancelados.");
        Bukkit.getScheduler().runTaskLater(this, () -> {
            PendingLogin current = pendingLogins.get(player.getUniqueId());
            if (current == pending && pendingLogins.remove(player.getUniqueId(), pending) && player.isOnline()) {
                player.sendMessage("§cPedido de login expirou. Use /ownerctl login novamente.");
            }
        }, windowSeconds * 20L);
    }

    private String addressKey(Player player) {
        InetSocketAddress address = player.getAddress();
        if (address != null && address.getAddress() != null) return address.getAddress().getHostAddress();
        return "uuid:" + player.getUniqueId();
    }

    private boolean isLocked(String key, long now) {
        AttemptState state = attemptsByAddress.get(key);
        return state != null && state.isLocked(now);
    }

    private AttemptResult noteFailure(String key, long now) {
        AttemptState state = attemptsByAddress.computeIfAbsent(key, ignored -> new AttemptState());
        int limit = Math.max(3, Math.min(10, getConfig().getInt("login-max-attempts", 5)));
        int lockSeconds = Math.max(30, Math.min(3600, getConfig().getInt("login-lockout-seconds", 60)));
        return state.noteFailure(now, limit, lockSeconds);
    }

    private LiteralCommandNode<CommandSourceStack> buildCommandTree() {
        return Commands.literal("ownerctl")
                .executes(context -> {
                    sendHelp(context.getSource().getSender());
                    return 1;
                })
                .then(Commands.literal("help").executes(context -> {
                    sendHelp(context.getSource().getSender());
                    return 1;
                }))
                .then(Commands.literal("ajuda").executes(context -> {
                    sendHelp(context.getSource().getSender());
                    return 1;
                }))
                .then(Commands.literal("login").executes(context -> {
                    handleLoginCommand(context.getSource().getSender());
                    return 1;
                }))
                .then(Commands.literal("logout").executes(context -> {
                    handleLogoutCommand(context.getSource().getSender());
                    return 1;
                }))
                .then(Commands.literal("status").executes(context -> {
                    handleStatusCommand(context.getSource().getSender());
                    return 1;
                }))
                .then(Commands.literal("version").executes(context -> {
                    context.getSource().getSender().sendMessage("§bOwnerLock §7" + getDescription().getVersion() + " §8| Paper 26.3");
                    return 1;
                }))
                .then(Commands.literal("audit")
                        .executes(context -> {
                            sendAudit(context.getSource().getSender(), 10);
                            return 1;
                        })
                        .then(Commands.argument("linhas", IntegerArgumentType.integer(1, 20)).executes(context -> {
                            sendAudit(context.getSource().getSender(), IntegerArgumentType.getInteger(context, "linhas"));
                            return 1;
                        })))
                .then(Commands.literal("console")
                        .then(Commands.argument("comando", StringArgumentType.greedyString()).executes(context -> {
                            dispatchOwnerConsole(context.getSource().getSender(), StringArgumentType.getString(context, "comando"));
                            return 1;
                        })))
                .build();
    }

    private void handleLoginCommand(CommandSender sender) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage("Este comando deve ser usado dentro do jogo.");
            return;
        }
        if (onlineMode) {
            if (!isConfiguredOnlineOwner(player)) {
                player.sendMessage("§cEsta conta não corresponde ao nick e UUID configurados.");
                return;
            }
            authenticatedSessions.add(player.getUniqueId());
            if (getConfig().getBoolean("auto-op-online", true) && !player.isOp()) player.setOp(true);
            player.sendMessage("§aIdentidade verificada pelo modo online. Sessão administrativa ativa.");
            return;
        }
        beginOfflineLogin(player);
    }

    private void handleLogoutCommand(CommandSender sender) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage("Use este comando dentro do jogo.");
            return;
        }
        if (onlineMode) {
            if (!isConfiguredOnlineOwner(player)) {
                player.sendMessage("§cEsta conta não corresponde ao nick e UUID configurados.");
                return;
            }
            player.sendMessage("§eNo modo online, o acesso segue seu UUID oficial; /logout não altera o OP persistente.");
            return;
        }
        if (!isConfiguredOwnerName(player)) {
            player.sendMessage("§cEsse nick não é o proprietário configurado.");
            return;
        }
        UUID id = player.getUniqueId();
        pendingLogins.remove(id);
        authenticatedSessions.remove(id);
        if (isConfiguredOwnerName(player)) player.setOp(false);
        audit(player, "offline admin logout; temporary OP revoked");
        player.sendMessage("§aSessão administrativa encerrada e OP temporária removida.");
    }

    private void handleStatusCommand(CommandSender sender) {
        if (!(sender instanceof Player player) || !hasAdminAccess(player)) {
            sender.sendMessage("§cSem autorização. Em modo offline, use /ownerctl login primeiro.");
            return;
        }
        sender.sendMessage("§8[§bOwnerLock§8] §aSessão administrativa ativa.");
        sender.sendMessage("§7Servidor online-mode: §f" + onlineMode);
        sender.sendMessage("§7Identidade: §f" + (onlineMode ? "UUID oficial + nick configurado" : "senha PBKDF2 + nick configurado"));
        sender.sendMessage("§7OP: §f" + (player.isOp() ? "ativo" : "inativo"));
        sender.sendMessage("§7Console remoto: §f" + (getConfig().getBoolean("console-enabled", true) ? "habilitado" : "desabilitado"));
    }

    private void dispatchOwnerConsole(CommandSender sender, String rawCommand) {
        if (!(sender instanceof Player player) || !hasAdminAccess(player)) {
            sender.sendMessage("§cSem autorização. Em modo offline, autentique com /ownerctl login.");
            return;
        }
        if (!getConfig().getBoolean("console-enabled", true)) {
            player.sendMessage("§cExecução de comandos pelo console está desativada na configuração.");
            return;
        }

        String command = rawCommand == null ? "" : rawCommand.trim();
        if (command.startsWith("/")) command = command.substring(1).trim();
        if (command.isBlank() || command.startsWith("/")) {
            player.sendMessage("§cInforme um único comando, sem barras extras.");
            return;
        }
        int maxLength = Math.max(64, Math.min(4096, getConfig().getInt("console-max-length", 512)));
        if (command.length() > maxLength) {
            player.sendMessage("§cComando muito longo. Limite configurado: " + maxLength + " caracteres.");
            return;
        }
        for (int index = 0; index < command.length(); index++) {
            char ch = command.charAt(index);
            if (Character.isISOControl(ch)) {
                player.sendMessage("§cO comando contém caracteres de controle proibidos.");
                return;
            }
        }

        String commandRoot = command.split("\\s+", 2)[0];
        String auditText = "console dispatch requested; root=" + commandRoot + "; length=" + command.length();
        if (getConfig().getBoolean("audit-log-command-text", false)) {
            auditText += "; command=" + command;
        }
        audit(player, auditText);
        boolean accepted = Bukkit.dispatchCommand(Bukkit.getConsoleSender(), command);
        player.sendMessage(accepted
                ? "§aComando enviado como console. A saída completa fica no console/log do servidor."
                : "§eO servidor não confirmou o comando; verifique a sintaxe no console/log.");
    }

    private void sendAudit(CommandSender sender, int count) {
        if (!(sender instanceof Player player) || !hasAdminAccess(player)) {
            sender.sendMessage("§cSem autorização.");
            return;
        }
        Path path = getDataFolder().toPath().resolve("owner-audit.log");
        if (!Files.isRegularFile(path)) {
            player.sendMessage("§eAinda não existe arquivo de auditoria.");
            return;
        }
        Deque<String> tail = new ArrayDeque<>();
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (tail.size() == count) tail.removeFirst();
                tail.addLast(line);
            }
        } catch (IOException exception) {
            player.sendMessage("§cNão foi possível ler a auditoria: " + exception.getMessage());
            return;
        }
        player.sendMessage("§8--- OwnerLock audit (últimas " + tail.size() + ") ---");
        for (String line : tail) {
            String visible = line.length() > 160 ? line.substring(0, 160) + "…" : line;
            player.sendMessage("§7" + visible);
        }
    }

    private boolean hasAdminAccess(Player player) {
        if (onlineMode) return isConfiguredOnlineOwner(player);
        return isConfiguredOwnerName(player) && authenticatedSessions.contains(player.getUniqueId());
    }

    private boolean isConfiguredOnlineOwner(Player player) {
        return ownerUuid != null && player.getUniqueId().equals(ownerUuid) && isConfiguredOwnerName(player);
    }

    private boolean isConfiguredOwnerName(Player player) {
        return player.getName().equalsIgnoreCase(ownerName);
    }

    private void sendHelp(CommandSender sender) {
        sender.sendMessage("§8§m--------------------------------");
        sender.sendMessage("§b§lOwnerLock §7- comandos do proprietário");
        sender.sendMessage("§f/ownerctl login §7- autenticar (senha obrigatória em modo offline)");
        sender.sendMessage("§f/ownerctl status §7- estado da sessão autenticada");
        sender.sendMessage("§f/ownerctl console <comando> §7- executar um comando como console");
        sender.sendMessage("§f/ownerctl audit [1-20] §7- ver linhas recentes da auditoria");
        sender.sendMessage("§f/ownerctl logout §7- encerrar a sessão offline e revogar OP temporária");
        sender.sendMessage("§f/ownerctl version §7- versão do plugin");
        sender.sendMessage("§cModo offline não prova identidade por nick/UUID; mantenha o servidor de teste privado.");
        sender.sendMessage("§8§m--------------------------------");
    }

    private void audit(Player player, String action) {
        writeAudit("player=" + player.getName() + " | uuid=" + player.getUniqueId() + " | action=" + action);
    }

    private void writeAudit(String record) {
        String safeRecord = sanitize(record);
        String line = Instant.now() + " | " + safeRecord;
        getLogger().info("OwnerLock AUDIT: " + line);
        if (!getConfig().getBoolean("audit-log", true)) return;
        Path path = getDataFolder().toPath().resolve("owner-audit.log");
        try {
            Files.createDirectories(path.getParent());
            Files.writeString(path, line + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException exception) {
            getLogger().warning("Could not append owner-audit.log: " + exception.getMessage());
        }
    }

    private String sanitize(String input) {
        StringBuilder clean = new StringBuilder(Math.min(input.length(), 600));
        for (int i = 0; i < input.length() && clean.length() < 600; i++) {
            char ch = input.charAt(i);
            clean.append(Character.isISOControl(ch) ? ' ' : ch);
        }
        return clean.toString();
    }

    private record PendingLogin(long expiresAtMillis, String attemptKey, Player playerReference) {}

    private record AttemptResult(int failures, int limit, boolean locked, int lockSeconds) {}

    private static final class AttemptState {
        private int failures;
        private long blockedUntilMillis;

        synchronized boolean isLocked(long now) {
            if (blockedUntilMillis > 0 && now >= blockedUntilMillis) {
                blockedUntilMillis = 0;
                failures = 0;
            }
            return now < blockedUntilMillis;
        }

        synchronized AttemptResult noteFailure(long now, int limit, int lockSeconds) {
            if (now < blockedUntilMillis) return new AttemptResult(failures, limit, true, lockSeconds);
            failures++;
            if (failures >= limit) {
                failures = 0;
                blockedUntilMillis = now + lockSeconds * 1000L;
                return new AttemptResult(limit, limit, true, lockSeconds);
            }
            return new AttemptResult(failures, limit, false, lockSeconds);
        }
    }
}
