-- Neovim sample: opentide LSP.
-- Disable yamlls on objects/**. Languages: opentide-yaml, kql, spl, esql, eql,
-- kuery (Kibana KQL), lucene (not sql).

vim.api.nvim_create_autocmd({ "BufRead", "BufNewFile" }, {
  pattern = { "objects/**/*.yaml", "objects/**/*.yml" },
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

for _, lang in ipairs({ "esql", "eql", "kuery", "lucene" }) do
  vim.api.nvim_create_autocmd({ "BufRead", "BufNewFile" }, {
    pattern = { "*." .. lang },
    callback = function()
      vim.bo.filetype = lang
    end,
  })
end

vim.api.nvim_create_autocmd("FileType", {
  pattern = { "opentide-yaml", "kql", "spl", "esql", "eql", "kuery", "lucene" },
  callback = function()
    vim.lsp.start({
      name = "opentide-lsp",
      cmd = { "opentide-lsp", "--stdio" },
      root_dir = vim.fs.root(0, { ".opentide", "objects", ".git" }),
    })
  end,
})
