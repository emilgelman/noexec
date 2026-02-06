import { describe, it, expect } from 'vitest';
import { detectCodeInjection } from '../code-injection';

describe('detectCodeInjection', () => {
  describe('eval/exec patterns', () => {
    it('should detect Python eval()', async () => {
      const result = await detectCodeInjection({
        command: 'user_input = request.get("code"); eval(user_input)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.detector).toBe('code-injection');
      expect(result?.message).toContain('eval()/exec()');
    });

    it('should detect Python exec()', async () => {
      const result = await detectCodeInjection({
        command: 'exec("print(" + user_input + ")")',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect JavaScript eval()', async () => {
      const result = await detectCodeInjection({
        command: 'const result = eval(req.body.code);',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect JavaScript Function constructor', async () => {
      const result = await detectCodeInjection({
        command: 'const fn = new Function(userInput);',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Ruby eval', async () => {
      const result = await detectCodeInjection({
        command: 'eval(params[:code])',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect PHP eval()', async () => {
      const result = await detectCodeInjection({
        command: 'eval($_GET["code"]);',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect PHP exec()', async () => {
      const result = await detectCodeInjection({
        command: 'exec("ls " . $_POST["dir"]);',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Python __import__()', async () => {
      const result = await detectCodeInjection({
        command: '__import__(user_module)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('dynamic imports', () => {
    it('should detect dynamic import with variable', async () => {
      const result = await detectCodeInjection({
        command: 'const module = await import(userInput);',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('dynamic import');
    });

    it('should detect dynamic import with concatenation', async () => {
      const result = await detectCodeInjection({
        command: 'import("./modules/" + moduleName)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect dynamic import with template literal', async () => {
      const result = await detectCodeInjection({
        command: 'import(`./plugins/${pluginName}`)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect require with concatenation', async () => {
      const result = await detectCodeInjection({
        command: 'require("./lib/" + libName)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Python __import__ with variable', async () => {
      const result = await detectCodeInjection({
        command: 'mod = __import__(module_name)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect importlib.import_module with variable', async () => {
      const result = await detectCodeInjection({
        command: 'importlib.import_module(user_module)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('template injection', () => {
    it('should detect Jinja2 SSTI with config', async () => {
      const result = await detectCodeInjection({
        command: 'template = "{{config.items()}}"',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('template injection');
    });

    it('should detect Jinja2 SSTI with __class__', async () => {
      const result = await detectCodeInjection({
        command: 'render_template("{{request.__class__}}")',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Jinja2 SSTI with __subclasses__', async () => {
      const result = await detectCodeInjection({
        command: '{{"".__class__.__bases__[0].__subclasses__()}}',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect JavaScript template literal injection', async () => {
      const result = await detectCodeInjection({
        command: 'const result = `${eval(userCode)}`;',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Python format with request', async () => {
      const result = await detectCodeInjection({
        command: 'msg = "Hello {}".format(request.args.get("name"))',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Server-Side Template Injection markers', async () => {
      const result = await detectCodeInjection({
        command: 'template = "${7*7}"',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('SQL injection', () => {
    it('should detect SQL injection with string concatenation (Python)', async () => {
      const result = await detectCodeInjection({
        command: 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('SQL injection');
    });

    it('should detect SQL injection with % formatting', async () => {
      const result = await detectCodeInjection({
        command: 'cursor.execute("SELECT * FROM users WHERE name = \'%s\'" % username)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect SQL injection with f-string', async () => {
      const result = await detectCodeInjection({
        command: 'cursor.execute(f"DELETE FROM users WHERE id = {user_id}")',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect JavaScript SQL injection', async () => {
      const result = await detectCodeInjection({
        command: 'db.query("SELECT * FROM users WHERE id = " + userId)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect JavaScript SQL injection with template literal', async () => {
      const result = await detectCodeInjection({
        command: 'db.query(`SELECT * FROM users WHERE name = ${username}`)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect PHP SQL injection', async () => {
      const result = await detectCodeInjection({
        command: 'mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET["id"])',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Ruby SQL injection', async () => {
      const result = await detectCodeInjection({
        command: 'User.find_by_sql("SELECT * FROM users WHERE name = #{params[:name]}")',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('command substitution', () => {
    it('should detect backticks with variables', async () => {
      const result = await detectCodeInjection({
        command: 'output = `ls ${userDir}`',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('Command injection');
    });

    it('should detect $() command substitution', async () => {
      const result = await detectCodeInjection({
        command: 'result = $(cat $file)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Python os.system with concatenation', async () => {
      const result = await detectCodeInjection({
        command: 'os.system("ping " + ip_address)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect subprocess with shell=True and concatenation', async () => {
      const result = await detectCodeInjection({
        command: 'subprocess.call("ls " + directory, shell=True)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect JavaScript exec with concatenation', async () => {
      const result = await detectCodeInjection({
        command: 'exec("ls " + directory)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Ruby backticks with interpolation', async () => {
      const result = await detectCodeInjection({
        command: 'output = `cat #{filename}`',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect PHP shell_exec with concatenation', async () => {
      const result = await detectCodeInjection({
        command: 'shell_exec("ls " . $dir);',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('unsafe deserialization', () => {
    it('should detect pickle.loads()', async () => {
      const result = await detectCodeInjection({
        command: 'data = pickle.loads(user_input)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('deserialization');
    });

    it('should detect pickle.load()', async () => {
      const result = await detectCodeInjection({
        command: 'pickle.load(file)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect yaml.load()', async () => {
      const result = await detectCodeInjection({
        command: 'config = yaml.load(file)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect yaml.unsafe_load()', async () => {
      const result = await detectCodeInjection({
        command: 'data = yaml.unsafe_load(content)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect JSON.parse with request data', async () => {
      const result = await detectCodeInjection({
        command: 'const data = JSON.parse(req.body.input)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect PHP unserialize', async () => {
      const result = await detectCodeInjection({
        command: 'unserialize($_POST["data"])',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Ruby Marshal.load', async () => {
      const result = await detectCodeInjection({
        command: 'Marshal.load(data)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('dynamic function calls', () => {
    it('should detect Python getattr with variable', async () => {
      const result = await detectCodeInjection({
        command: 'getattr(obj, user_method)()',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('dynamic function call');
    });

    it('should detect PHP call_user_func', async () => {
      const result = await detectCodeInjection({
        command: 'call_user_func($func_name, $arg)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect PHP variable function', async () => {
      const result = await detectCodeInjection({
        command: '$func_name()',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('safe patterns (should NOT trigger)', () => {
    it('should allow ast.literal_eval (safe)', async () => {
      const result = await detectCodeInjection({
        command: 'data = ast.literal_eval(user_input)',
      });
      expect(result).toBeNull();
    });

    it('should allow yaml.safe_load', async () => {
      const result = await detectCodeInjection({
        command: 'config = yaml.safe_load(file)',
      });
      expect(result).toBeNull();
    });

    it('should allow yaml.load with SafeLoader', async () => {
      const result = await detectCodeInjection({
        command: 'data = yaml.load(file, Loader=yaml.SafeLoader)',
      });
      expect(result).toBeNull();
    });

    it('should allow parameterized SQL queries (Python)', async () => {
      const result = await detectCodeInjection({
        command: 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
      });
      expect(result).toBeNull();
    });

    it('should allow parameterized SQL queries (Python list)', async () => {
      const result = await detectCodeInjection({
        command: 'cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])',
      });
      expect(result).toBeNull();
    });

    it('should allow prepared statements', async () => {
      const result = await detectCodeInjection({
        command: 'stmt = conn.prepare("SELECT * FROM users WHERE id = ?")',
      });
      expect(result).toBeNull();
    });

    it('should allow subprocess without shell=True', async () => {
      const result = await detectCodeInjection({
        command: 'subprocess.run(["ls", directory])',
      });
      expect(result).toBeNull();
    });

    it('should allow comments mentioning eval', async () => {
      const result = await detectCodeInjection({
        command: '# Do not use eval() here',
      });
      expect(result).toBeNull();
    });

    it('should allow string literals with eval', async () => {
      const result = await detectCodeInjection({
        command: 'print("eval is dangerous")',
      });
      expect(result).toBeNull();
    });

    it('should allow safe variable usage', async () => {
      const result = await detectCodeInjection({
        command: 'const result = calculate(userInput)',
      });
      expect(result).toBeNull();
    });

    it('should allow safe imports', async () => {
      const result = await detectCodeInjection({
        command: 'import os',
      });
      expect(result).toBeNull();
    });

    it('should allow static require', async () => {
      const result = await detectCodeInjection({
        command: 'const fs = require("fs")',
      });
      expect(result).toBeNull();
    });

    it('should allow getattr with string literal (safer)', async () => {
      const result = await detectCodeInjection({
        command: 'getattr(obj, "method_name")',
      });
      expect(result).toBeNull();
    });
  });
});
