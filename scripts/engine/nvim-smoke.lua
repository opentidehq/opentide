-- Neovim headless smoke test (#185 P2.8): Neovim's own LSP client attaches
-- to opentide-lsp and shows each diagnostic once (a client given both push
-- and pull diagnostics would show it twice).
--
--   nvim --headless --clean -l scripts/nvim-smoke.lua target/debug/opentide-lsp
local bin = assert(arg[1], "usage: nvim -l scripts/nvim-smoke.lua <opentide-lsp>")
local dir = vim.fn.tempname()
vim.fn.mkdir(dir, "p")
local file = dir .. "/typo.kql"
vim.fn.writefile({ "SecurityEvent | wher EventID == 4688" }, file)

local function fail(message)
  io.stderr:write("nvim-smoke: " .. message .. "\n")
  os.exit(1)
end

vim.cmd.edit(file)
local buf = vim.api.nvim_get_current_buf()
vim.bo[buf].filetype = "kql"
local client_id = vim.lsp.start({
  name = "opentide",
  cmd = { bin, "--stdio" },
  root_dir = dir,
})
if not client_id then
  fail("the client did not start")
end
if not vim.wait(15000, function()
  return #vim.diagnostic.get(buf) > 0
end, 50) then
  fail("no diagnostics within 15 s")
end
-- Give a second (pushed or pulled) set the time to arrive.
vim.wait(1000)
local diagnostics = vim.diagnostic.get(buf)
local codes = {}
for _, d in ipairs(diagnostics) do
  table.insert(codes, tostring(d.code))
end
if #diagnostics ~= 1 or codes[1] ~= "kql_unknown_operator" then
  fail("expected one kql_unknown_operator, got " .. vim.inspect(codes))
end
local client = vim.lsp.get_client_by_id(client_id)
local caps = client.server_capabilities
if caps.positionEncoding ~= "utf-16" then
  fail("positionEncoding " .. vim.inspect(caps.positionEncoding))
end
print(("nvim-smoke: %s, one diagnostic (%s), %s diagnostics"):format(
  vim.version().major .. "." .. vim.version().minor,
  codes[1],
  caps.diagnosticProvider and "pulled" or "pushed"
))
-- `stop_client` reads the same on Neovim 0.9 (Ubuntu's) and later.
vim.lsp.stop_client(client_id)
vim.wait(1000)
os.exit(0)
