# fastapi-auth-audit

扫 FastAPI 项目里缺鉴权依赖的路由函数——找出「不登录就能调」的接口。

## 为什么用 AST 不用正则

要判断的是「这个函数**没有** `Depends(...)`」。找缺失必须先知道参数列表的边界，
而边界是括号配对——正则只有有限状态，表达不了（需要下推自动机）。
顺带解决另外三个问题：注释和字符串里的同名文本、跨行签名、函数体里调用同名函数。

## 用法

```
python auth_audit.py ./app
python auth_audit.py ./app --auth get_current_admin require_user --exclude auth.py login.py
```

发现问题退出码 1，可直接接 CI 或 pre-commit。

## 路径要指到「该有鉴权的那个目录」

这是最容易用错的地方。指向整个 app 时，公开接口（登录、健康检查、用户端 API）会被全部报成漏洞。
在一个真实项目上实测：指整个 app 报 17 处，指到管理端子目录报 0 处——那 17 处本来就该公开。

**先定范围，再定规则。** 范围错了，规则再准也是噪音。

## 认得的两种写法

```python
@router.get("/x")
def f(user=Depends(get_current_user)): ...          # 函数级

router = APIRouter(dependencies=[Depends(get_current_user)])   # router 级，整个文件生效
```

## 局限

- 只认 `Depends(x)`，认不出自定义装饰器
- 只判断「有没有挂」，不判断鉴权函数内部逻辑对不对
- 认不出 `@app.middleware("http")` 或函数体里手写的 `if not user: raise 401`

## 试一下

```
python auth_audit.py example
```

`api/items.py:9  list_items` —— 故意漏了鉴权的那一个。
