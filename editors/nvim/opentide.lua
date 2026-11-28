-- Neovim sample: opentide LSP.
-- Disable yamlls on objects/**. Languages: opentide-yaml, kql, spl, esql, eql,
-- kuery (Kibana KQL), lucene, falco (Falco conditions), cql (CrowdStrike
-- Query Language), yara, exabeam (Exabeam Query Language), yaral (YARA-L),
-- datadog (the Datadog log search syntax), and opentide-config for .opentide/configurations/**/*.toml (not sql).
-- Configuration checks need `opentide lsp start`: `opentide-lsp` on its own
-- reports nothing there. Cassandra's CQL uses *.cql too: drop
-- "cql" from the loop below where a workspace holds Cassandra scripts.
-- Runs on Neovim 0.9 and later.

-- The workspace folder of the current buffer: the closest folder above it
-- that holds one of `markers` (vim.fs.root, from Neovim 0.10; vim.fs.find
-- before it), else the working directory.
local function root_dir(markers)
  if vim.fs.root then
    return vim.fs.root(0, markers)
  end
  local found = vim.fs.find(markers, {
    path = vim.fs.dirname(vim.api.nvim_buf_get_name(0)),
    upward = true,
  })[1]
  return found and vim.fs.dirname(found) or vim.fn.getcwd()
end

vim.api.nvim_create_autocmd({ "BufRead", "BufNewFile" }, {
  -- A path with a slash matches the whole file name: `*/objects/...` an
  -- absolute one, `objects/...` one typed from the workspace folder.
  pattern = { "*/objects/**/*.yaml", "*/objects/**/*.yml", "objects/**/*.yaml", "objects/**/*.yml" },
  callback = function()
    vim.bo.filetype = "opentide-yaml"
  end,
})

vim.api.nvim_create_autocmd({ "BufRead", "BufNewFile" }, {
  pattern = { "*.kql" },
  callback = function()
    vim.bo.filetype = "kql"
  end,
})

vim.api.nvim_create_autocmd({ "BufRead", "BufNewFile" }, {
  pattern = { "*.spl" },
  callback = function()
    vim.bo.filetype = "spl"
  end,
})

-- YARA: `.yar` and `.yara`, filetype `yara` (Neovim's own filetype name).
vim.api.nvim_create_autocmd({ "BufRead", "BufNewFile" }, {
  pattern = { "*.yar", "*.yara" },
  callback = function()
    vim.bo.filetype = "yara"
  end,
})

-- YARA-L (Google SecOps): `.yaral` and `.yl2`, filetype `yaral`.
vim.api.nvim_create_autocmd({ "BufRead", "BufNewFile" }, {
  pattern = { "*.yaral", "*.yl2" },
  callback = function()
    vim.bo.filetype = "yaral"
  end,
})

for _, lang in ipairs({ "esql", "eql", "kuery", "lucene", "falco", "cql", "exabeam", "datadog" }) do
  vim.api.nvim_create_autocmd({ "BufRead", "BufNewFile" }, {
    pattern = { "*." .. lang },
    callback = function()
      vim.bo.filetype = lang
    end,
  })
end

-- Configuration TOML keeps the TOML grammar; a generic TOML server
-- (taplo) does not attach to the opentide-config filetype.
vim.treesitter.language.register("toml", "opentide-config")
vim.api.nvim_create_autocmd({ "BufRead", "BufNewFile" }, {
  pattern = { "*/.opentide/configurations/*.toml", "*/.opentide/configurations/**/*.toml" },
  callback = function()
    vim.bo.filetype = "opentide-config"
  end,
})

vim.api.nvim_create_autocmd("FileType", {
  pattern = { "opentide-config" },
  callback = function()
    vim.lsp.start({
      name = "opentide",
      cmd = { "opentide", "lsp", "start" },
      root_dir = root_dir({ ".opentide", ".git" }),
    })
  end,
})

vim.api.nvim_create_autocmd("FileType", {
  pattern = { "opentide-yaml", "kql", "spl", "esql", "eql", "kuery", "lucene", "falco", "cql", "yara", "exabeam", "yaral", "datadog" },
  callback = function()
    vim.lsp.start({
      name = "opentide-lsp",
      cmd = { "opentide-lsp", "--stdio" },
      root_dir = root_dir({ ".opentide", "objects", ".git" }),
    })
  end,
})
