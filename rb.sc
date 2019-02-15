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
    "&#x2460; &#x1F58B;&#xFE0F; Developers write code",
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
    "&#x2461; &#x1F333; Commit to Source Control",
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
    "&#x2462; &#x1F3D7;&#xFE0F; Built and packaged",
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
    "&#x2463; &#x1F6A2; Package is distributed",
    List("Compromised distribution infra"),
    List("Signatures") // unsolved, but out of scope
  ),
  Step(
    "&#x2464; &#x1F60D; User runs software",
    List(),
    List(),
    List("&#x1F945; No malicious code here"),
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

val processRows: List[Row] = 
  model.map(step => Row(step.name, step.objectives, Nil))

def fragment[T](in: List[T]): List[List[T]] =
  in.foldLeft(List.empty[List[T]]){
    case (Nil, elem) => List(List(elem))
    case (acc, elem) => acc :+ (acc.last :+ elem)
  }

val processModelFragmented: List[List[Row]] =
  fragment[Row](processRows)

val process: List[Page] = processModelFragmented.map(rows => Page(
  "OSS Development and Distribution",
  "Steps",
  "",
  rows
))

 
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

println((process ++ threatModelPages ++ mitigationsPages).mkString("\n---\n"))
