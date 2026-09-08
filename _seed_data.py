"""为端到端验证准备测试数据：白名单 + 项目各一个（含版本）。"""
import json
import urllib.request

BASE = "http://127.0.0.1:8099/api"

POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.20</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
  </dependencies>
</project>"""


def post(path, payload):
    req = urllib.request.Request(BASE + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=120) as r:
        return json.loads(r.read().decode())


r1 = post("/whitelists/import", {"pom_text": POM})
print("whitelist import:", r1.get("owner_id"))
r2 = post("/projects/import", {"pom_text": POM, "name": "演示项目"})
print("project import:", r2.get("owner_id"))
print("whitelists:", [(o["id"], o["name"]) for o in get("/whitelists")])
print("projects:", [(o["id"], o["name"]) for o in get("/projects")])
