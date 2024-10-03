-- local dap = require 'dap'
--
-- dap.configurations.cpp = {
--   {
--     name = 'Launch test file',
--     type = 'codelldb',
--     request = 'launch',
--     program = 'build/dev/test/libhyphanet_test',
--     cwd = '${workspaceFolder}',
--     stopOnEntry = false,
--   },
-- }

vim.api.nvim_create_autocmd('User', {
  pattern = 'LazyDone',
  callback = function()
    local lint = require 'lint'
    if lint ~= nil then
      local cppcheck = lint.linters.cppcheck
      cppcheck.args = {
        '--enable=warning,style,performance,information',
        '--project=' .. vim.fn.getcwd() .. '/build/dev/compile_commands.json',
        function()
          if vim.bo.filetype == 'cpp' then
            return '--language=c++'
          else
            return '--language=c'
          end
        end,
        '--inline-suppr',
        '--quiet',
        '--template={file}:{line}:{column}: [{id}] {severity}: {message}',
        '--suppress=missingIncludeSystem',
      }
      cppcheck.append_fname = false
      -- print(vim.inspect(cppcheck))
    else
      print 'lint not found'
    end
  end,
})
