
lazy val commonSettings = Seq(
  organization := "com.waywardcode",
  version := "1.0",
  scalaVersion := "2.11.8"
)


lazy val lib = (project in file("lib")).
  settings(commonSettings: _*).
  settings(
    name := "spritz"
  )
  
lazy val cmd = (project in file("cmd")).
  settings(commonSettings: _*).
  settings(
    name := "spritz_cmd"
  ).
  dependsOn(lib)
