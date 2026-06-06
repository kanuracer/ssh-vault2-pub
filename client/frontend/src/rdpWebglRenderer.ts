export type RDPRenderEndpoint = {sessionId:string; url:string; width:number; height:number};

export type RDPBinaryFrame = {
  seq: bigint;
  left: number;
  top: number;
  width: number;
  height: number;
  surfaceWidth: number;
  surfaceHeight: number;
  stride: number;
  format: number;
  pixels: Uint8Array;
};

const MAGIC = 'SVRDP1';
const HEADER_LEN = 54;

export function parseRDPBinaryFrame(data: ArrayBuffer): RDPBinaryFrame {
  if (data.byteLength < HEADER_LEN) throw new Error(`RDP frame too small: ${data.byteLength}`);
  const magic = String.fromCharCode(...new Uint8Array(data, 0, 6));
  if (magic !== MAGIC) throw new Error('RDP frame magic mismatch');
  const v = new DataView(data);
  const payloadLen = v.getUint32(50, true);
  if (HEADER_LEN + payloadLen > data.byteLength) throw new Error('RDP frame payload truncated');
  const width = v.getUint32(22, true);
  const height = v.getUint32(26, true);
  const stride = v.getUint32(38, true);
  if (!width || !height || stride < width * 4) throw new Error('RDP frame geometry invalid');
  return {
    seq: v.getBigUint64(6, true),
    left: v.getUint32(14, true),
    top: v.getUint32(18, true),
    width,
    height,
    surfaceWidth: v.getUint32(30, true),
    surfaceHeight: v.getUint32(34, true),
    stride,
    format: v.getUint8(42),
    pixels: new Uint8Array(data, HEADER_LEN, payloadLen)
  };
}

function compileShader(gl: WebGL2RenderingContext, type: number, source: string): WebGLShader {
  const shader = gl.createShader(type);
  if (!shader) throw new Error('WebGL shader allocation failed');
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(shader) || 'WebGL shader compile failed');
  return shader;
}

function createProgram(gl: WebGL2RenderingContext): WebGLProgram {
  const vs = compileShader(gl, gl.VERTEX_SHADER, `#version 300 es
in vec2 a_pos;
in vec2 a_uv;
out vec2 v_uv;
void main(){ v_uv = a_uv; gl_Position = vec4(a_pos, 0.0, 1.0); }`);
  const fs = compileShader(gl, gl.FRAGMENT_SHADER, `#version 300 es
precision mediump float;
uniform sampler2D u_tex;
in vec2 v_uv;
out vec4 color;
void main(){ color = texture(u_tex, v_uv); }`);
  const program = gl.createProgram();
  if (!program) throw new Error('WebGL program allocation failed');
  gl.attachShader(program, vs); gl.attachShader(program, fs); gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(program) || 'WebGL link failed');
  return program;
}

export class RDPWebGLRenderer {
  private gl: WebGL2RenderingContext;
  private program: WebGLProgram;
  private texture: WebGLTexture;
  private vao: WebGLVertexArrayObject;
  private surfaceWidth = 0;
  private surfaceHeight = 0;

  constructor(private canvas: HTMLCanvasElement) {
    const gl = canvas.getContext('webgl2', {antialias:false, alpha:false, desynchronized:true});
    if (!gl) throw new Error('WebGL2 nicht verfügbar');
    this.gl = gl;
    this.program = createProgram(gl);
    const texture = gl.createTexture();
    const vao = gl.createVertexArray();
    if (!texture || !vao) throw new Error('WebGL resource allocation failed');
    this.texture = texture;
    this.vao = vao;
    gl.bindVertexArray(vao);
    const vertices = new Float32Array([
      -1, -1, 0, 1,
       1, -1, 1, 1,
      -1,  1, 0, 0,
       1,  1, 1, 0,
    ]);
    const buf = gl.createBuffer();
    if (!buf) throw new Error('WebGL buffer allocation failed');
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, vertices, gl.STATIC_DRAW);
    const pos = gl.getAttribLocation(this.program, 'a_pos');
    const uv = gl.getAttribLocation(this.program, 'a_uv');
    gl.enableVertexAttribArray(pos);
    gl.vertexAttribPointer(pos, 2, gl.FLOAT, false, 16, 0);
    gl.enableVertexAttribArray(uv);
    gl.vertexAttribPointer(uv, 2, gl.FLOAT, false, 16, 8);
    gl.bindTexture(gl.TEXTURE_2D, texture);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.pixelStorei(gl.UNPACK_ALIGNMENT, 1);
  }

  present(frame: RDPBinaryFrame) {
    this.presentBatch([frame]);
  }

  presentBatch(frames: RDPBinaryFrame[]) {
    if (!frames.length) return;
    for (const frame of frames) this.upload(frame);
    this.draw();
  }

  private ensureSurface(frame: RDPBinaryFrame) {
    const gl = this.gl;
    if (frame.surfaceWidth !== this.surfaceWidth || frame.surfaceHeight !== this.surfaceHeight) {
      this.surfaceWidth = Math.max(1, frame.surfaceWidth);
      this.surfaceHeight = Math.max(1, frame.surfaceHeight);
      this.canvas.width = this.surfaceWidth;
      this.canvas.height = this.surfaceHeight;
      gl.viewport(0, 0, this.surfaceWidth, this.surfaceHeight);
      gl.bindTexture(gl.TEXTURE_2D, this.texture);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, this.surfaceWidth, this.surfaceHeight, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
    }
    if (frame.left < 0 || frame.top < 0 || frame.left + frame.width > this.surfaceWidth || frame.top + frame.height > this.surfaceHeight) {
      throw new Error('RDP frame outside surface');
    }
  }

  private upload(frame: RDPBinaryFrame) {
    const gl = this.gl;
    this.ensureSurface(frame);
    const y = Math.max(0, frame.top);
    gl.bindTexture(gl.TEXTURE_2D, this.texture);
    if (frame.format !== 1) throw new Error('unsupported RDP frame format');
    const rowBytes = frame.width * 4;
    let pixels = frame.pixels;
    if (frame.stride !== rowBytes) {
      const compact = new Uint8Array(rowBytes * frame.height);
      for (let y = 0; y < frame.height; y++) compact.set(pixels.subarray(y * frame.stride, y * frame.stride + rowBytes), y * rowBytes);
      pixels = compact;
    }
    gl.texSubImage2D(gl.TEXTURE_2D, 0, frame.left, y, frame.width, frame.height, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
  }

  private draw() {
    const gl = this.gl;
    gl.useProgram(this.program);
    gl.bindVertexArray(this.vao);
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
  }

  setSharp(sharp: boolean) {
    const gl = this.gl;
    gl.bindTexture(gl.TEXTURE_2D, this.texture);
    const mode = sharp ? gl.NEAREST : gl.LINEAR;
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, mode);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, mode);
  }

  dispose() {
    const gl = this.gl;
    gl.deleteTexture(this.texture);
    gl.deleteProgram(this.program);
    gl.deleteVertexArray(this.vao);
  }
}
