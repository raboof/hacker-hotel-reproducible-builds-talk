case class Step(
                 name: String,
                 threats: List[String],
                 mitigations: List[String],
                 objectives: List[String] = Nil,
               ) {
  def left = objectives ++ threats
  override def toString =
    s"""
       |$name
       |Threats:
       |${threats.map(t => "* " + t).mkString("\n")}
     """.stripMargin
}

val model = List(
  Step(
    "Developers write code",
    List(
      "Malicious contributors",
      "Blackmail, coercion",
      "Compromised dev machine",
    ),
    List(
      "Cannot be prevented",
      "Can we still improve trust?",
    )
  ),
  Step(
    "Commit to Source Control",
    List(
      "Compromised SCM hosting"
    ),
    List(
      "Signed commits",
      "Detect 'rewriting history'",
      "Audits", // automatic and manual
      // Anyone can do this!
    )
  ),
  Step(
    "Built and packaged",
    List(
      "Malicious dependencies/plugins",
      "Compromised build machine",
    ),
    List(
      "Transitive verification",
      "!!!"
    )
  ),
  Step(
    "Package is distributed",
    List("Compromised distribution infra"),
    List("Signatures") // unsolved, but out of scope
  ),
  Step(
    "User runs software",
    List(),
    List(),
    List("No malicious code here"),
  )
)

case class Row(
              name: String,
              left: List[String],
              right: List[String]
              )

case class Page(name: String, leftHead: String, rightHead: String, rows: List[Row]) {
  override def toString =
  s"""
$name

<table>
<tr><th>$leftHead</th><th>$rightHead</th></tr>
${rows.map { row =>
  s"""
     |<tr><td>
     |${row.name}
     |<ul>
     |${row.left.map(line => s"<li>$line</li>").mkString("\n")}
     |</ul>
     |</td><td>
     |<ul>
     |${row.right.map(line => s"<li>$line</li>").mkString("\n")}
     |</ul>
     |</td></tr>
   """.stripMargin
}.mkString("\n")}
</table>
  """
}

val process: Page = Page(
  "OSS Development and Distribution",
  "Steps",
  "",
  model.map(step => Row(step.name, step.objectives, Nil))
)

//val threatModel: Page =
//  Page(
//    "Threat model",
//    "Threats",
//    "",
//    model.map(step => Row(step.name, step.left, List.empty)))

val threatModelFragmented: List[List[Step]] = {
  def removeLast(step: List[Step]): List[Step] = {
    if (step.last.threats.isEmpty) removeLast(step.init) :+ step.last
    else step.init :+ step.last.copy(threats = step.last.threats.init)
  }
  def fragment(steps: List[Step]): List[List[Step]] = {
    if (steps.flatMap(_.threats).isEmpty)
      Nil
    else
      fragment(removeLast(steps)) :+ steps
  }
  fragment(model)
}

val threatModelPages =
  threatModelFragmented.map(steps =>
    Page("Threat model", "Threats", "", steps.map(step => Row(step.name, step.left, List.empty)))
  )


val mitigationsFragmented: List[List[Step]] = {
  def removeLast(step: List[Step]): List[Step] = {
    if (step.last.mitigations.isEmpty) removeLast(step.init) :+ step.last
    else step.init :+ step.last.copy(mitigations = step.last.mitigations.init)
  }
  def fragment(steps: List[Step]): List[List[Step]] = {
    if (steps.flatMap(_.mitigations).isEmpty)
      Nil
    else
      fragment(removeLast(steps)) :+ steps
  }
  fragment(model)
}

val mitigationsPages: List[Page] =
  mitigationsFragmented.map(steps =>
    Page("Threat model", "Threats", "Mitigations", steps.map(step => Row(step.name, step.left, step.mitigations)))
  )

println((process +: (threatModelPages ++ mitigationsPages)).mkString("\n---\n"))
