import { useEffect, useRef } from "react";
import * as THREE from "three";

export default function AnimatedSphere({ className }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const scene = new THREE.Scene();
    const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x000000, 0);

    const camera = new THREE.PerspectiveCamera(45, 0.75, 0.1, 100);
    camera.position.set(0, 0, 4);

    const ambientLight = new THREE.AmbientLight(0xffffff, 0.8);
    scene.add(ambientLight);

    const pointLight = new THREE.PointLight(0x76d6ff, 1.2);
    pointLight.position.set(4, 2, 5);
    scene.add(pointLight);

    const geometry = new THREE.IcosahedronGeometry(1.2, 4);
    const material = new THREE.MeshStandardMaterial({
      color: 0x22c55e,
      roughness: 0.2,
      metalness: 0.4,
      emissive: 0x0c4b3d,
      emissiveIntensity: 0.35,
    });
    const sphere = new THREE.Mesh(geometry, material);
    scene.add(sphere);

    const wireframe = new THREE.Mesh(
      new THREE.IcosahedronGeometry(1.6, 2),
      new THREE.MeshBasicMaterial({
        color: 0x38bdf8,
        wireframe: true,
        opacity: 0.4,
        transparent: true,
      }),
    );
    scene.add(wireframe);

    function resizeRenderer() {
      const parent = canvas.parentElement;
      if (!parent) return;
      const width = parent.clientWidth;
      const height = parent.clientHeight;
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height);
    }

    resizeRenderer();
    window.addEventListener("resize", resizeRenderer);

    let frameId = null;
    const animate = () => {
      sphere.rotation.y += 0.006;
      sphere.rotation.x += 0.004;
      wireframe.rotation.y -= 0.0025;
      renderer.render(scene, camera);
      frameId = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      window.removeEventListener("resize", resizeRenderer);
      if (frameId) cancelAnimationFrame(frameId);
      renderer.dispose();
      geometry.dispose();
      material.dispose();
      wireframe.geometry.dispose();
      wireframe.material.dispose();
    };
  }, []);

  return <div className={className}><canvas ref={canvasRef} className="h-full w-full block" /></div>;
}
